import "pe"
rule _Trojan_Autorun_Trojan_GenericKDZ_94847_226_1_Trojan_Autorun_Tro_551 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKDZ.94847_226_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_332_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_440_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.l0Z@a8rAQKh.vir, Virus.Hijack_Gen.Trojan.ShellObject.l0Z@a8rAQKh_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.l0Z@a8rAQKh_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.l0Z@a8rAQKh_3.vir, Virus.Hijack_Trojan.Agent.DQQO_427.vir, Virus.Hijack_Trojan.Agent.DQQO_94.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2a2975e047d98e848f71487780dbc98443f07ee5270aab606e2ce11b58188cd"
    hash2       = "6e02048fd5e756658e70501dd62ca54f86459669b40f98b5fa4d4784bcf03065"
    hash3       = "799e9454ae80483edd8a22bcddaf11a0fef1e68b8d0cbf0e67a05aab8a4e1087"
    hash4       = "5c8f74b4c246ef68dda2adfc0d1ac248a7deab3e872ba23b1c074e593bbaa964"
    hash5       = "3c203e50d2141ecc31504091e3981fae73ead3b440f78cdcb2851cb990248318"
    hash6       = "439735eb30e948432726954686e3473617e742d87890143741e92c86fb0186f9"
    hash7       = "2b324f9a151893d2387df8f7920e1b3e09157cbfb734a17815f4cb3375c90b69"
    hash8       = "ec96af166f96d64cc66bbe62c6679b0d5bb7a582a26bfbaf61bc5b7eb181f2f2"
    hash9       = "dbd72d6dc1d79bc7b56f4b5f77fb6d4e449919e7f880824e33fb432149fba9fe"
    hash10      = "ade4509dc4bd510da93897fd6887f2f31ac1dd38a04931d8937baa5cb5bf0834"

  strings:
    $s1 = "Preconfigured system-to-system XML-based dialogs for the relevant E-Business Suite Application(s) are provided" fullword ascii
    $s2 = "only to reinstall the software on the licensed compu" fullword ascii
    $s3 = "delivery. Oracle also warrants that services ordered will be provided in a professional manner consistent with industry#" fullword ascii
    $s4 = "dors, so that they can use the information to improve how their products run with" fullword ascii
    $s5 = "6. Digital Certificates. The software uses digital certificates. These digital certificates confirm the identityand software ven" ascii
    $s6 = "6. Digital Certificates. The software uses digital certificates. These digital certificates confirm the identityand software ven" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "e0694fdfb223f0597230804c2f630838" and (all of them)
    ) or (all of them)
}