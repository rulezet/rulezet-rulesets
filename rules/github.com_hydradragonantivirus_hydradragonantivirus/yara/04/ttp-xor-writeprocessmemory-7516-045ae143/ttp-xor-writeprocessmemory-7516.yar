rule TTP_XOR_WriteProcessMemory_7516 {
  strings:
    $key_7516 = { 22 64 [2] 10 46 [2] 16 73 [2] 38 73 [2] 07 6f }

  condition:
    any of them
}