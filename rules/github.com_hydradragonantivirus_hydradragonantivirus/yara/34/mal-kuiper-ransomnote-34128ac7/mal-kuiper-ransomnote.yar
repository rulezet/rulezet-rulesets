rule MAL_Kuiper_ransomnote {
    meta:
        description = "Matches strings found in Stairwell analysis blog post of Kuiper ransomware."
        last_modified = "2024-01-23"
        author = "@petermstewart"
        DaysofYara = "23/100"
        ref = "https://stairwell.com/resources/kuiper-ransomware-analysis-stairwells-technical-report/"

    strings:
        $tox = "D27A7B3711CD1442A8FAC19BB5780FF291101F6286A62AD21E5F7F08BD5F5F1B9803AAC6ECF9"
        $email = "kuipersupport@onionmail.org"
        $a1 = "Your network has been compromised! All your important data has been encrypted!"
        $a2 = "There is  only one way to get your data back to normal:"
        $a3 = "1. Contact us as soon as possible to avoid damages and losses from your business."
        $a4 = "2. Send to us any encrypted file of your choice and your personal key."
        $a5 = "3. We will decrypt 1 file for test (maximum file size = 1 MB), its guaranteed that we can decrypt your files."
        $a6 = "4. Pay the amount required in order to restore your network back to normal."
        $a7 = "5. We will then send you our software to decrypt and will guide you through the whole restoration of your network."
        $a8 = "We prefer Monero (XMR) - FIXED PRICE"
        $a9 = "We accept Bitcoin (BTC) - 20% extra of total payment!"
        $a10 = "WARNING!"
        $a11 = "Do not rename encrypted data."
        $a12 = "Do not try to decrypt using third party software, it may cause permanent data loss not being able to recover."
        $a13 = "Contact information:"
        $a14 = "In order to contact us, download with the following software: https://qtox.github.io or https://tox.chat/download.html"
        $a15 = "Then just add us in TOX:"
        $a16 = "Your personal id:"
        $a17 = "--------- Kuiper Team ------------"

    condition:
        filesize < 5KB and
        15 of them
}