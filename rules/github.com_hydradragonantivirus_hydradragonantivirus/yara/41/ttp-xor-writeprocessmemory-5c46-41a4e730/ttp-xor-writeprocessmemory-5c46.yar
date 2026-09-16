rule TTP_XOR_WriteProcessMemory_5c46 {
  strings:
    $key_5c46 = { 0b 34 [2] 39 16 [2] 3f 23 [2] 11 23 [2] 2e 3f }

  condition:
    any of them
}