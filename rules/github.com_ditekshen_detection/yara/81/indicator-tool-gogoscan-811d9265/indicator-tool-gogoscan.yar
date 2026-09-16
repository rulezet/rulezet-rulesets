rule INDICATOR_TOOL_GoGoScan {
    meta:
        author = "ditekSHen"
        description = "Detects GoGo scan tool"
    strings:
        $s1 = "(conn) (scan  (scan) MB in  Value>" ascii
        $s2 = "sweep sysmontargettelnet" ascii
        $s3 = "%d bytes(?i) (.*SESS.*?ID)([a-z0-9])([A-Z]+)" ascii
        $s4 = "prepareForSweep" ascii
        $s5 = "Scanned %s with %d ports, found %d" ascii
        $s6 = "/chainreactors/gogo/" ascii
        $s7 = "Starting task %s ,total ports: %d , mod: %s" ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}