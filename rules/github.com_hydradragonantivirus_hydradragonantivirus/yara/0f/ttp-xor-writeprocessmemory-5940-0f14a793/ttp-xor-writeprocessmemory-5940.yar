rule TTP_XOR_WriteProcessMemory_5940 {
  strings:
    $key_5940 = { 0e 32 [2] 3c 10 [2] 3a 25 [2] 14 25 [2] 2b 39 }

  condition:
    any of them
}