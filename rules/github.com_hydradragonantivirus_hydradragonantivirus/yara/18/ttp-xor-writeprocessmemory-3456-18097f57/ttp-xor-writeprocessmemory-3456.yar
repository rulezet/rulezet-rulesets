rule TTP_XOR_WriteProcessMemory_3456 {
  strings:
    $key_3456 = { 63 24 [2] 51 06 [2] 57 33 [2] 79 33 [2] 46 2f }

  condition:
    any of them
}