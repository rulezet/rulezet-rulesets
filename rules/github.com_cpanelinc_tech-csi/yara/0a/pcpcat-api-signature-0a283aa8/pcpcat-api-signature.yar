rule PCPcat_API_Signature {
    meta:
        description = "PCPcat C2 API communication pattern"
    strings:
        $s1 = "/domains?client=" nocase
        $s2 = "/result" nocase
        $s3 = "\"env\":" nocase
        $s4 = "67.217.57.240:5656"
    condition:
        all of them
}