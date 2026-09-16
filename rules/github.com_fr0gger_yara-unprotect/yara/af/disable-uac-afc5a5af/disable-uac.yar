rule Disable_UAC 
{
    meta:
        author = "x0r"
        description = "Disable User Access Control"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Security Center" nocase
        $r1 = "UACDisableNotify"
    condition:
        all of them
}