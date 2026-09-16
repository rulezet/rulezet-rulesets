rule TTP_XOR_WriteProcessMemory_4c16 {
  strings:
    $key_4c16 = { 1b 64 [2] 29 46 [2] 2f 73 [2] 01 73 [2] 3e 6f }

  condition:
    any of them
}