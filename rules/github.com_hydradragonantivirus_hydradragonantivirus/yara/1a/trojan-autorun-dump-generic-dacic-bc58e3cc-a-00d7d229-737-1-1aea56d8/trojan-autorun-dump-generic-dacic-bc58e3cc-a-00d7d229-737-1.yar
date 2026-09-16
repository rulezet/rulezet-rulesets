rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_737_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_737_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ee63112ea6ba96a42ce213b01df8e3277447ac51791f16f21233a38b3b0f516"

  strings:
    $s1  = "sgraphic(0xD829, 0, 0, -1, -1, 0, 0, library(ieframe.dll))" fullword wide
    $s2  = "icon(0x796B, 16rp, 16rp, library(ieframe.dll))" fullword wide
    $s3  = "atom(description)" fullword wide
    $s4  = "atom(version)" fullword wide
    $s5  = "rect(5rp, 0rp, 5rp, 5rp)" fullword wide
    $s6  = "rect(25rp, 20rp, 10rp, 0rp)" fullword wide
    $s7  = "rect(25rp, 10rp, 30rp, 0rp)" fullword wide
    $s8  = "atom(KBnum)" fullword wide
    $s9  = "atom(productID)" fullword wide
    $s10 = "atom(cWrap)" fullword wide
    $s11 = "atom(upgradeBox)" fullword wide
    $s12 = "atom(uacIcon)" fullword wide
    $s13 = "rect(0rp, 0rp, 6rp, 0rp)" fullword wide
    $s14 = "atom(text_checkbox)" fullword wide
    $s15 = "atom(copyright)" fullword wide
    $s16 = "atom(OKButton)" fullword wide
    $s17 = "size(70rp,26rp)" fullword wide
    $s18 = "atom(GPBanner)" fullword wide
    $s19 = "rect(0rp, 0rp, 7rp, 0rp)" fullword wide
    $s20 = "atom(GroupPolicyLink)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}