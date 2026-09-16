rule TTP_XOR_WriteProcessMemory_72a7 {
  strings:
    $key_72a7 = { 25 d5 [2] 17 f7 [2] 11 c2 [2] 3f c2 [2] 00 de }

  condition:
    any of them
}