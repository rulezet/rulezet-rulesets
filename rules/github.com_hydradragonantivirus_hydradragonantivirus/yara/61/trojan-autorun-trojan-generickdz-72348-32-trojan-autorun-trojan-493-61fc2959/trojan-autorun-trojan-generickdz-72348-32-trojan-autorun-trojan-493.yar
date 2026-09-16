import "pe"
rule _Trojan_Autorun_Trojan_GenericKDZ_72348_32_Trojan_Autorun_Trojan_493 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKDZ.72348_32.vir, Trojan.Autorun_Trojan.GenericKDZ.72348_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9095cd5e9bdc26e02c362b2136b0ac47d229c0b03c9c3a3a78ec238ae6266f09"
    hash2       = "2d11f7d84579b5b166f2720f78631e5767e1ee50e5d351d403c8816a5ba1391e"

  strings:
    $s1  = "of licenses required. For the iSupport, iStore and Configurator programs, only the processorPrivacy Statement connect to Microso" ascii
    $s2  = "of licenses required. For the iSupport, iStore and Configurator programs, only the processorPrivacy Statement connect to Microso" ascii
    $s3  = "Notice of Dispute to you by U.S. Mail to your address if we have it, or otherwise to your e-mail address.erface Processes" fullword ascii
    $s4  = "ft or service provider computer systems over the Internet. In some" fullword ascii
    $s5  = "activation is meant to identify unauthorized changes to the licensing or activation functions of the the software. The component" ascii
    $s6  = "activation is meant to identify unauthorized changes to the licensing or activation functions of the the software. The component" ascii
    $s7  = "individual is " fullword ascii
    $s8  = " or your copy of it " fullword ascii
    $s9  = "y license it." fullword ascii
    $s10 = "s of the software are licensed as a single unit. You may" fullword ascii
    $s11 = "Full Time Equivalent (FTE) Student: is defined as any full-time student enrolle" fullword ascii
    $s12 = "ware? We do not sell our software or your copy of it " fullword ascii
    $s13 = "ed as an employee or contractor whose time or labor (piece work) or absences are managed by the" fullword ascii
    $s14 = "YOU PAID Oentered electronically from other sources must be licensed separately." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "436159bc380fb5e1c01f4c24b6a7a126" and (8 of them)
    ) or (all of them)
}