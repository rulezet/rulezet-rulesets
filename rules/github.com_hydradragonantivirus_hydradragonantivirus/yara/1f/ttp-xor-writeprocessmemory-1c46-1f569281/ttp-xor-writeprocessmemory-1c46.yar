rule TTP_XOR_WriteProcessMemory_1c46 {
  strings:
    $key_1c46 = { 4b 34 [2] 79 16 [2] 7f 23 [2] 51 23 [2] 6e 3f }

  condition:
    any of them
}