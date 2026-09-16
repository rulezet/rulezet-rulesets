rule mimikatz_sekurlsa {
    strings:
        $s1 = { 33 DB 8B C3 48 83 C4 20 5B C3 }
        $s2 = {83 64 24 30 00 44 8B 4C 24 48 48 8B 0D}
        $s3 = {83 64 24 30 00 44 8B 4D D8 48 8B 0D}
        $s4 = {84 C0 74 44 6A 08 68}
        $s5 = {8B F0 3B F3 7C 2C 6A 02 6A 10 68}
        $s6 = {8B F0 85 F6 78 2A 6A 02 6A 10 68}

    condition:
        all of them
}