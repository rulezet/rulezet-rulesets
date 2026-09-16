rule TTP_XOR_WriteProcessMemory_3c16 {
  strings:
    $key_3c16 = { 6b 64 [2] 59 46 [2] 5f 73 [2] 71 73 [2] 4e 6f }

  condition:
    any of them
}