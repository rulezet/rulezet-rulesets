rule TTP_XOR_WriteProcessMemory_2516 {
  strings:
    $key_2516 = { 72 64 [2] 40 46 [2] 46 73 [2] 68 73 [2] 57 6f }

  condition:
    any of them
}