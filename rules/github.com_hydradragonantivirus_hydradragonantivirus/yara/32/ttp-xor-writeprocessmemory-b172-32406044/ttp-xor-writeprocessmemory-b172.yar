rule TTP_XOR_WriteProcessMemory_b172 {
  strings:
    $key_b172 = { e6 00 [2] d4 22 [2] d2 17 [2] fc 17 [2] c3 0b }

  condition:
    any of them
}