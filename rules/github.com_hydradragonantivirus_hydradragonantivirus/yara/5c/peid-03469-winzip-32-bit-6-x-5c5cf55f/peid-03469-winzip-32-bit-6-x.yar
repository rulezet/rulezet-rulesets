rule PEiD_03469_WinZip__32_bit__6_x_ {
  meta:
    description = "[WinZip (32-bit) 6.x]"
    ep_only     = "true"

  strings:
    $a = { FF 15 FC 81 40 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 }

  condition:
    $a
}