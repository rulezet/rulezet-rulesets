rule DeerStealer {
    meta:
        author = "ANY.RUN"
        date = "2024-07-18"
        sha256 = "d9db8cdef549e4ad0e33754d589a4c299e7082c3a0b5efdee1a0218a0a1bf1ee"
    strings:
        $s1 = { 48 8b 84 24 [4]                 48 8b 84 24 [4]                 48 8b 44 [2]                    48 8b 44 [2]                    48 8b 05 }                        
        $s2 = { 48 8b 44 24 ??                  48 8b 4c 24 ??                  ff d0                           e9 [4]                          48 8b 44 24 ??                  ff d0}          
    condition:
        uint16(0) == 0x5a4d and any of them
}