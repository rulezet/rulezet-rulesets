rule TTP_XOR_WriteProcessMemory_65e6 {
  strings:
    $key_65e6 = { 32 94 [2] 00 b6 [2] 06 83 [2] 28 83 [2] 17 9f }

  condition:
    any of them
}