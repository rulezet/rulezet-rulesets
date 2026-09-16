rule TTP_XOR_WriteProcessMemory_b106 {
  strings:
    $key_b106 = { e6 74 [2] d4 56 [2] d2 63 [2] fc 63 [2] c3 7f }

  condition:
    any of them
}