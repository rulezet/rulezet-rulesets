rule INDICATOR_TOOL_ReverseSSH_Go {
   meta:
        author = "ditekShen"
        description = "Detects golang reverse ssh tool"
    strings:
        $s1 = "/reverse_ssh/" ascii
        $s2 = "main.rsshService" ascii
    condition:
       uint16(0) == 0x5a4d and all of them
}