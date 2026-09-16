rule PEiD_00636_EXECryptor_vx_x_x_x_ {
  meta:
    description = "[EXECryptor vx.x.x.x]"
    ep_only     = "true"

  strings:
    $a = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 }

  condition:
    $a
}