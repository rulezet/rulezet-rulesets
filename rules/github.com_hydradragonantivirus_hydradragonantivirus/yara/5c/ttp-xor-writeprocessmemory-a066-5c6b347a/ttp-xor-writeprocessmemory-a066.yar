rule TTP_XOR_WriteProcessMemory_a066 {
  strings:
    $key_a066 = { f7 14 [2] c5 36 [2] c3 03 [2] ed 03 [2] d2 1f }

  condition:
    any of them
}