rule TTP_XOR_WriteProcessMemory_62a7 {
  strings:
    $key_62a7 = { 35 d5 [2] 07 f7 [2] 01 c2 [2] 2f c2 [2] 10 de }

  condition:
    any of them
}