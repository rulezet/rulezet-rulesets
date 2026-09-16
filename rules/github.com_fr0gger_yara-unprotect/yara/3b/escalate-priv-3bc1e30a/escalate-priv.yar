rule Escalate_Priv 
{
    meta:
        author = "x0r"
        description = "Escalade priviledges"
    strings:
        $d1 = "Advapi32.dll" nocase
        $c1 = "SeDebugPrivilege" 
        $c2 = "AdjustTokenPrivileges" 
    condition:
        1 of ($d*) and 1 of ($c*)
}