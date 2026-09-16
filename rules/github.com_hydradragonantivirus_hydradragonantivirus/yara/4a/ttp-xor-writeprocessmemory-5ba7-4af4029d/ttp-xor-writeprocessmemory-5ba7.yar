rule TTP_XOR_WriteProcessMemory_5ba7 {
  strings:
    $key_5ba7 = { 0c d5 [2] 3e f7 [2] 38 c2 [2] 16 c2 [2] 29 de }

  condition:
    any of them
}