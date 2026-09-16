rule PEiD_00629_EXECryptor_v1_3_0_45_ {
  meta:
    description = "[EXECryptor v1.3.0.45]"
    ep_only     = "true"

  strings:
    $a = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 }

  condition:
    $a
}