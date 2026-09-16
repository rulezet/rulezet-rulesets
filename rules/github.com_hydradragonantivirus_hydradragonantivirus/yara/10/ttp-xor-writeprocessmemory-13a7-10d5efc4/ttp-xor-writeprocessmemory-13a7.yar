rule TTP_XOR_WriteProcessMemory_13a7 {
  strings:
    $key_13a7 = { 44 d5 [2] 76 f7 [2] 70 c2 [2] 5e c2 [2] 61 de }

  condition:
    any of them
}