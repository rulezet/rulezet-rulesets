rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_27_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_27_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71eafede1f40a5c6a164523d3e6b3c06d60f4d061bdfd7aaa10ab0d47061ac14"

  strings:
    $s1 = "Boo.Lang.Runtime.RuntimeServices+<Coerce>c__AnonStorey1B" fullword ascii
    $s2 = "BUY CRYPT FROM PULSAR CRYPTER - @PulsarCrypter_bot" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}