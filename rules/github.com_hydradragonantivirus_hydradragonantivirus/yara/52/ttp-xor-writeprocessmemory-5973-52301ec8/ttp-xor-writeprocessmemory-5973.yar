rule TTP_XOR_WriteProcessMemory_5973 {
  strings:
    $key_5973 = { 0e 01 [2] 3c 23 [2] 3a 16 [2] 14 16 [2] 2b 0a }

  condition:
    any of them
}