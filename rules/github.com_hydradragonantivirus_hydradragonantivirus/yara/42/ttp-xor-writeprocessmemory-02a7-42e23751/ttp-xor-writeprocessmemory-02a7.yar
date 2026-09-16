rule TTP_XOR_WriteProcessMemory_02a7 {
  strings:
    $key_02a7 = { 55 d5 [2] 67 f7 [2] 61 c2 [2] 4f c2 [2] 70 de }

  condition:
    any of them
}