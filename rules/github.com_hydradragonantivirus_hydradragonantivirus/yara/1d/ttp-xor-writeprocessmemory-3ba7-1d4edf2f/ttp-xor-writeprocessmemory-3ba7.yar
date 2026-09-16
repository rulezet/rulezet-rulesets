rule TTP_XOR_WriteProcessMemory_3ba7 {
  strings:
    $key_3ba7 = { 6c d5 [2] 5e f7 [2] 58 c2 [2] 76 c2 [2] 49 de }

  condition:
    any of them
}