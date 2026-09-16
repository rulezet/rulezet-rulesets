rule TTP_XOR_WriteProcessMemory_5f40 {
  strings:
    $key_5f40 = { 08 32 [2] 3a 10 [2] 3c 25 [2] 12 25 [2] 2d 39 }

  condition:
    any of them
}