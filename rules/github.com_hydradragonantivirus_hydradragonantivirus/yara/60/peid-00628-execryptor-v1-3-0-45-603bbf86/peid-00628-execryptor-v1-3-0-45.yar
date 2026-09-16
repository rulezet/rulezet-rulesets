rule PEiD_00628_EXECryptor_v1_3_0_45_ {
  meta:
    description = "[EXECryptor v1.3.0.45]"
    ep_only     = "true"

  strings:
    $a = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 }

  condition:
    $a
}