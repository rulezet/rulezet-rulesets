rule MAL_Cactus_ransomnote {
    meta:
        description = "Matches strings found in ransom notes dropped by Cactus ransomware."
        last_modified = "2024-03-23"
        author = "@petermstewart"
        DaysofYara = "83/100"
        
    strings:
        $a1 = "cactusbloguuodvqjmnzlwetjlpj6aggc6iocwhuupb47laukux7ckid.onion"
        $a2 = "sonarmsng5vzwqezlvtu2iiwwdn3dxkhotftikhowpfjuzg7p3ca5eid.onion"
        $a3 = "cactus2tg32vfzd6mwok23jfeolh4yxrg2obzlsyax2hfuka3passkid.onion"
        $b1 = "encrypted by Cactus"
        $b2 = "Do not interrupt the encryption process"
        $b3 = "Otherwise the data may be corrupted"
        $b4 = "wait until encryption is finished"
        $b6 = "TOX (https://tox.chat):"
        $b7 = "7367B422CD7498D5F2AAF33F58F67A332F8520CF0279A5FBB4611E0121AE421AE1D49ACEABB2"

    condition:
        filesize < 5KB and
        1 of ($a*) or
        5 of ($b*)
}