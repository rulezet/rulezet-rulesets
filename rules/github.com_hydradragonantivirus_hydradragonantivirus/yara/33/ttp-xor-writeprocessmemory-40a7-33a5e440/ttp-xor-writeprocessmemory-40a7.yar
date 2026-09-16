rule TTP_XOR_WriteProcessMemory_40a7 {
  strings:
    $key_40a7 = { 17 d5 [2] 25 f7 [2] 23 c2 [2] 0d c2 [2] 32 de }

  condition:
    any of them
}