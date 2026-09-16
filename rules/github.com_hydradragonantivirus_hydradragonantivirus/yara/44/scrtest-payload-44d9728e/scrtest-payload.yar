rule scrtest_payload {
    strings:
        $s1 = "Consysqq.dll"
        $s2 = "Main"
        $s3 = "%c%c%c%c%c%c.exe"
        $s4 = "agmkis2\x00"

    condition:
        uint16be(0) == 0x4d5a and all of them
}