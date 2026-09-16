rule M_Utility_GHOSTTOWN_1 {
    meta:
        author = "Mandiant"
    strings:
        $code1 = { 2F 76 61 72 2F 6C 6F 67 } 
        $code2 = { 2F 76 61 72 2F 72 75 6E } 
        $debug1 = "=== results ===" ascii
        $debug2 = "=== %s ===" ascii
        $debug3 = "searching record in file %s" ascii
        $debug4 = "record not matched, not modifing %s" ascii
        $debug5 = "delete %d records in %s" ascii
        $debug6 = "NEVER_LOGIN" ascii
        $debug7 = "you need to specify a username to clear" ascii
        $pattern1 = "%-10s%-10s%-10s%-20s%-10s" ascii
        $pattern2 = "%-15s%-10s%-15s%-10s" ascii
    condition:
        uint32(0) == 0x464C457F and all of them
}