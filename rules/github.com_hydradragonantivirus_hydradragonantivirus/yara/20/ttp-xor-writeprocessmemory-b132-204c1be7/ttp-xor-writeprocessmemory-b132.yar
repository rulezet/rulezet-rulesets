rule TTP_XOR_WriteProcessMemory_b132 {
  strings:
    $key_b132 = { e6 40 [2] d4 62 [2] d2 57 [2] fc 57 [2] c3 4b }

  condition:
    any of them
}