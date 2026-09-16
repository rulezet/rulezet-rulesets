rule TTP_XOR_WriteProcessMemory_15a7 {
  strings:
    $key_15a7 = { 42 d5 [2] 70 f7 [2] 76 c2 [2] 58 c2 [2] 67 de }

  condition:
    any of them
}