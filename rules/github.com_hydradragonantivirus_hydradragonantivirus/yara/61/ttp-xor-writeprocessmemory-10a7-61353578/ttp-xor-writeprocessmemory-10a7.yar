rule TTP_XOR_WriteProcessMemory_10a7 {
  strings:
    $key_10a7 = { 47 d5 [2] 75 f7 [2] 73 c2 [2] 5d c2 [2] 62 de }

  condition:
    any of them
}