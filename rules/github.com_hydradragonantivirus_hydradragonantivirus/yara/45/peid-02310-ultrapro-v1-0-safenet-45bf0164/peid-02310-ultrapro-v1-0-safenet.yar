rule PEiD_02310_UltraPro_V1_0____SafeNet_ {
  meta:
    description = "[UltraPro V1.0 -> SafeNet]"
    ep_only     = "true"

  strings:
    $a = { A1 ?? ?? ?? ?? 85 C0 0F 85 3B 06 00 00 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 }

  condition:
    $a
}