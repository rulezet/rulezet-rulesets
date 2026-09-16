rule TTP_XOR_WriteProcessMemory_a026 {
  strings:
    $key_a026 = { f7 54 [2] c5 76 [2] c3 43 [2] ed 43 [2] d2 5f }

  condition:
    any of them
}