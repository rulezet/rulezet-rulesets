rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef1ccbfff7b5646df96025b5a8db6af84a31cbd01c10a1d661aab8ee3f90678b"

  strings:
    $s1  = "Thread Error: %s (%d)=Error decoding URL style (%%XX) encoded string at position %d1Invalid URL encoded character (%s) at positi" wide
    $s2  = "Variable not found: %s=Component does not support scripting. Class: %0:s, Name: %1:s.Object does not support scripting. Class: %" wide
    $s3  = "DGetting the Count of a TComponentsEnumerator object is not supported<Errors object must support the interface IIterateIntfSuppo" wide
    $s4  = "OLE error %.8x.Method '%s' not supported by automation object/Variant does not reference an automation object7Dispatch methods d" wide
    $s5  = "Script engine not found: %s." fullword wide
    $s6  = "Can't find included page: %s\"Page %s does not support inclusionInclude file %s includes itself+Cannot create script engine: %s" wide
    $s7  = "Component %s not found" fullword wide
    $s8  = "Host@~A" fullword ascii
    $s9  = "%s<input type=\"hidden\" name=\"%s\" value=\"%s\">%s" fullword ascii
    $s10 = "#Parameter %d required for method %s/Method definition for %s has over %d parameters!Too many parameters for method %s'Adapter R" wide
    $s11 = "Index@8" fullword ascii
    $s12 = "Name@8" fullword ascii
    $s13 = "Query(" fullword ascii
    $s14 = "Self@8" fullword ascii
    $s15 = "Designing(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}