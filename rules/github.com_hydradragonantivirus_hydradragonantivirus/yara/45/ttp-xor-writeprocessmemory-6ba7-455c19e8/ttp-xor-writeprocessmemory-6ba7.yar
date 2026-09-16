rule TTP_XOR_WriteProcessMemory_6ba7 {
  strings:
    $key_6ba7 = { 3c d5 [2] 0e f7 [2] 08 c2 [2] 26 c2 [2] 19 de }

  condition:
    any of them
}