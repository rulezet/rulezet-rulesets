import "pe"
rule o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker_x64 {
  meta:
    description = "conti - file o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker_x64.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-11-29"
    hash1       = "31656dcea4da01879e80dff59a1af60ca09c951fe5fc7e291be611c4eadd932a"

  strings:
    $s1  = "conti_v3.dll" fullword ascii
    $s2  = "AppPolicyGetProcessTerminationMethod" fullword ascii
    $s3  = "operator co_await" fullword ascii
    $s4  = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
    $s5  = "api-ms-win-core-file-l1-2-2" fullword wide  
    $s6  = "__swift_2" fullword ascii
    $s7  = "__swift_1" fullword ascii
    $s8  = "expand 32-byte k" fullword ascii  
    $s9  = "u3HcH<H" fullword ascii  
    $s10 = "D$XD9x" fullword ascii  
    $s11 = "delete" fullword ascii  
    $s12 = "ue!T$(H!T$ " fullword ascii
    $s13 = "L$&8\\$&t,8Y" fullword ascii
    $s14 = "F 2-by" fullword ascii
    $s15 = "u\"8Z(t" fullword ascii
    $s16 = "L$ |+L;" fullword ascii
    $s17 = "vB8_(t" fullword ascii
    $s18 = "ext-ms-" fullword wide
    $s19 = "OOxq*H" fullword ascii
    $s20 = "H97u+A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 600KB and
    (pe.imphash() == "137fa89046164fe07e0dd776ed7a0191" or all of them)
}