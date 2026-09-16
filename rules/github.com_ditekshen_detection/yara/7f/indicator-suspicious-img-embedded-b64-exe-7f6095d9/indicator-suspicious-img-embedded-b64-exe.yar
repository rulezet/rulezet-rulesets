rule INDICATOR_SUSPICIOUS_IMG_Embedded_B64_EXE {
    meta:
        author = "ditekSHen"
        description = "Detects images with specific base64 markers and/or embedding (reversed) base64-encoded executables"
    strings:
        $m1 = "<<BASE64_START>>" ascii
        $m2 = "<<BASE64_END>>" ascii
        $m3 = "BASE64_START" ascii
        $m4 = "BASE64_END" ascii
        $m5 = "BASE64-START" ascii
        $m6 = "BASE64-END" ascii
        $m7 = "BASE64START" ascii
        $m8 = "BASE64END" ascii
        $h1 = "TVqQA" ascii
        $h2 = "AQqVT" ascii
    condition:
        (uint32(0) == 0xd8ff or uint32(0) == 0x474e5089 or uint16(0) == 0x4d42) and ((2 of ($m*)) or (1 of ($h*)))
}