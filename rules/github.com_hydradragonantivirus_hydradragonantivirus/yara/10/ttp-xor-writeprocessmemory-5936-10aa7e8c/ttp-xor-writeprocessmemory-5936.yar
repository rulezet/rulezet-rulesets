rule TTP_XOR_WriteProcessMemory_5936 {
  strings:
    $key_5936 = { 0e 44 [2] 3c 66 [2] 3a 53 [2] 14 53 [2] 2b 4f }

  condition:
    any of them
}