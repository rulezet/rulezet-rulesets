rule TTP_XOR_WriteProcessMemory_b1e7 {
  strings:
    $key_b1e7 = { e6 95 [2] d4 b7 [2] d2 82 [2] fc 82 [2] c3 9e }

  condition:
    any of them
}