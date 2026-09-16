rule TTP_XOR_WriteProcessMemory_1b16 {
  strings:
    $key_1b16 = { 4c 64 [2] 7e 46 [2] 78 73 [2] 56 73 [2] 69 6f }

  condition:
    any of them
}