rule PEiD_03470_WinZip_32_bit_SFX_v6_x_module_ {
  meta:
    description = "[WinZip 32-bit SFX v6.x module]"
    ep_only     = "true"

  strings:
    $a = { FF 15 ?? ?? ?? 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 38 08 74 06 40 80 38 00 75 F6 80 38 00 74 01 40 33 C9 ?? ?? ?? ?? FF 15 }

  condition:
    $a
}