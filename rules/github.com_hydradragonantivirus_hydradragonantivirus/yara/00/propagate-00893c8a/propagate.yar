import "pe"
rule PROPagate
{
    meta:
        author = "McAfee ATR - Thomas Roccia - @fr0gger_ "
        description = "Detect Window Properties Modfication"
        reference = "http://www.hexacorn.com/blog/2017/10/26/propagate-a-new-code-injection-trick/"
        mitre_id = "T1055"
    strings:
        $func1 = "SetProp" nocase
        $func2 = "FindWindows" nocase
        $func3 = "GetProp" nocase
        $var1 = "UxSubclassInfo" nocase
        $var2 = "CC32SubclassInfo" nocase
    condition:
        uint16(0) == 0x5A4D and ($func1 and $func3 and ($var1 or $var2) or (all of them) or
        pe.imports("User32.dll", "SetProp") and
        pe.imports("User32.dll", "GetProp"))
}