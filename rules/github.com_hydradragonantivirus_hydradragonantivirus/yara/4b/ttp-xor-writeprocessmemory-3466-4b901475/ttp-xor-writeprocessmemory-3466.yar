rule TTP_XOR_WriteProcessMemory_3466 {
  strings:
    $key_3466 = { 63 14 [2] 51 36 [2] 57 03 [2] 79 03 [2] 46 1f }

  condition:
    any of them
}