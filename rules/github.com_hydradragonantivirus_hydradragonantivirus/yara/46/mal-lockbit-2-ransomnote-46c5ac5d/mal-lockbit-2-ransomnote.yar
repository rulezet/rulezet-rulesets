rule MAL_Lockbit_2_ransomnote {
    meta:
        description = "Matches strings found in Lockbit 2.0 ransom note samples."
        last_modified = "2024-01-19"
        author = "@petermstewart"
        DaysofYara = "19/100"

    strings:
        $a = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion"
        $b1 = "https://bigblog.at"
        $b2 = "http://lockbitsup4yezcd5enk5unncx3zcy7kw6wllyqmiyhvanjj352jayid.onion"
        $b3 = "http://lockbitsap2oaqhcun3syvbqt6n5nzt7fqosc6jdlmsfleu3ka4k2did.onion"
        $c1 = "LockBit 2.0 Ransomware"
        $c2 = "Your data are stolen and encrypted"
        $c3 = "The data will be published on TOR website"
        $c4 = "if you do not pay the ransom"
        $c5 = "You can contact us and decrypt on file for free on these TOR sites"
        $c6 = "Decryption ID:"

    condition:
        filesize < 5KB and
        $a and
        2 of ($b*) and
        5 of ($c*)
}