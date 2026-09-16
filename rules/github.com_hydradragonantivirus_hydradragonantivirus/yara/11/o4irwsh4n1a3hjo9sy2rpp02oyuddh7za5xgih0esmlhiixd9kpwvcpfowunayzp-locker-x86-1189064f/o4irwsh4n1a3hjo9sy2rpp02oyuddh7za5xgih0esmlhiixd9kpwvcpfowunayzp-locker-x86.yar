import "pe"
rule o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker_x86 {
  meta:
    description = "conti - file o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker_x86.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-11-29"
    hash1       = "01a9549c015cfcbff4a830cea7df6386dc5474fd433f15a6944b834551a2b4c9"

  strings:
    $s1  = "conti_v3.dll" fullword ascii
    $s2  = "AppPolicyGetProcessTerminationMethod" fullword ascii
    $s3  = "6 7/787E7[7" fullword ascii  
    $s4  = "operator co_await" fullword ascii
    $s5  = "2%3.3f3~3" fullword ascii  
    $s6  = "1\"1&1,:4:<:D:L:T:\\:d:l:t:|:" fullword ascii
    $s7  = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
    $s8  = "SVWjEhQ" fullword ascii
    $s9  = "__swift_2" fullword ascii
    $s10 = "__swift_1" fullword ascii
    $s11 = "api-ms-win-core-file-l1-2-2" fullword wide  
    $s12 = "7K7P7T7X7\\7" fullword ascii  
    $s13 = "7h7o7v7}7" fullword ascii  
    $s14 = "O0a0s0" fullword ascii  
    $s15 = ";?;I;S;" fullword ascii  
    $s16 = "8>8C8Q8V8" fullword ascii  
    $s17 = "QQSVj8j@" fullword ascii
    $s18 = "5-5X5s5" fullword ascii  
    $s19 = "expand 32-byte k" fullword ascii  
    $s20 = "delete" fullword ascii  

  condition:
    uint16(0) == 0x5a4d and filesize < 600KB and
    (pe.imphash() == "749dc5143e9fc01aa1d221fb9a48d5ea" or all of them)
}