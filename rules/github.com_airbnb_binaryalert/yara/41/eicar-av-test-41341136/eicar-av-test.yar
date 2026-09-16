rule eicar_av_test {
    

    meta:
        description = "This is a standard AV test, intended to verify that BinaryAlert is working correctly."
        author = "Austin Byers | Airbnb CSIRT"
        reference = "http://www.eicar.org/86-0-Intended-use.html"

    strings:
        $eicar_regex = /^X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*\s*$/

    condition:
        all of them
}