rule TTP_XOR_WriteProcessMemory_61a7 {
  strings:
    $key_61a7 = { 36 d5 [2] 04 f7 [2] 02 c2 [2] 2c c2 [2] 13 de }

  condition:
    any of them
}