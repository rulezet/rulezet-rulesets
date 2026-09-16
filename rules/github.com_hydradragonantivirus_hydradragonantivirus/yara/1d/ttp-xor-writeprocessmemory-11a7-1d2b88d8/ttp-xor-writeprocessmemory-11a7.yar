rule TTP_XOR_WriteProcessMemory_11a7 {
  strings:
    $key_11a7 = { 46 d5 [2] 74 f7 [2] 72 c2 [2] 5c c2 [2] 63 de }

  condition:
    any of them
}