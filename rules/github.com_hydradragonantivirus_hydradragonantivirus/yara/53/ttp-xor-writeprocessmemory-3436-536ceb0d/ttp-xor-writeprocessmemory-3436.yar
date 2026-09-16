rule TTP_XOR_WriteProcessMemory_3436 {
  strings:
    $key_3436 = { 63 44 [2] 51 66 [2] 57 53 [2] 79 53 [2] 46 4f }

  condition:
    any of them
}