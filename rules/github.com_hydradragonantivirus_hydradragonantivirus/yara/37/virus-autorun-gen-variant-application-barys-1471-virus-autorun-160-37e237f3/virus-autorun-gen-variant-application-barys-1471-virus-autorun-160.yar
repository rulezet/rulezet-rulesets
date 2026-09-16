rule _Virus_Autorun_Gen_Variant_Application_Barys_1471_Virus_Autorun__160 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Gen.Variant.Application.Barys.1471.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_1.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_236_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36bbc80169bd128d160fb3869dcf23891b69a7765d8abb171897c9dfd0d58e3a"
    hash2       = "0ea76f5343284061fe91a1363d0a2116b76db249e7de5cc17a6971f30f805011"
    hash3       = "c25118c87134ffa298b9ec21b6abbfb10ced5f41dee519e34b593db27e0ce502"
    hash4       = "0895cf813e2dd5ededf0d1e6c5e4e5c3b937abb5a48b6d2a0ca93c03bb3019a9"

  strings:
    $s1 = "-type %c is not supported because Solaris doors are not supported on the platform find was compiled on." fullword ascii
    $s2 = "warning: you have specified the %s option after a non-option argument %s, but options are not positional (%s affects tests speci" ascii
    $s3 = " cost=%s rate=%#03.2g %sside effects " fullword ascii
    $s4 = "warning: Unix filenames usually don't contain slashes (though pathnames do).  That means that '%s %s' will probably evaluate to " ascii
    $s5 = "false all the time on this system.  You might find the '-wholename' test more useful, or perhaps '-samefile'.  Alternatively, if" ascii
    $s6 = " you are using GNU grep, you could use 'find ... -print0 | grep -FzZ %s'." fullword ascii
    $s7 = "fied before it as well as those specified after it).  Please specify options before other arguments." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}