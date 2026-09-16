rule TTP_XOR_WriteProcessMemory_55a7 {
  strings:
    $key_55a7 = { 02 d5 [2] 30 f7 [2] 36 c2 [2] 18 c2 [2] 27 de }

  condition:
    any of them
}