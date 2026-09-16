rule TTP_XOR_WriteProcessMemory_0ba7 {
  strings:
    $key_0ba7 = { 5c d5 [2] 6e f7 [2] 68 c2 [2] 46 c2 [2] 79 de }

  condition:
    any of them
}