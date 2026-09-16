rule TTP_XOR_WriteProcessMemory_3373 {
  strings:
    $key_3373 = { 64 01 [2] 56 23 [2] 50 16 [2] 7e 16 [2] 41 0a }

  condition:
    any of them
}