rule eicar_substring_test {
    

    meta:
        description = "Standard AV test, checking for an EICAR substring"
        author = "Austin Byers | Airbnb CSIRT"

    strings:
        $eicar_substring = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

    condition:
        all of them
}