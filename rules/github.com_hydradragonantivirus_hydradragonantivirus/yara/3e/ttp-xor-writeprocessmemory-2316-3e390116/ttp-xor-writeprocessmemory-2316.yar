rule TTP_XOR_WriteProcessMemory_2316 {
  strings:
    $key_2316 = { 74 64 [2] 46 46 [2] 40 73 [2] 6e 73 [2] 51 6f }

  condition:
    any of them
}