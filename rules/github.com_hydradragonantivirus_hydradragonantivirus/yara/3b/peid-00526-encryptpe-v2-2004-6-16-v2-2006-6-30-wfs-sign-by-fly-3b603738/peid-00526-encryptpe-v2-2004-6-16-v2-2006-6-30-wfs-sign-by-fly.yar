rule PEiD_00526_EncryptPE_V2_2004_6_16_V2_2006_6_30____WFS___Sign_by_fly_ {
  meta:
    description = "[EncryptPE V2.2004.6.16-V2.2006.6.30 -> WFS ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { 60 9C 64 FF 35 00 00 00 00 E8 7A 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a
}