rule TTP_XOR_WriteProcessMemory_a072 {
  strings:
    $key_a072 = { f7 00 [2] c5 22 [2] c3 17 [2] ed 17 [2] d2 0b }

  condition:
    any of them
}