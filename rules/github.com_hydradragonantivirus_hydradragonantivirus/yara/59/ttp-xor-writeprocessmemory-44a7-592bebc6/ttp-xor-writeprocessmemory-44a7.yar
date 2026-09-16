rule TTP_XOR_WriteProcessMemory_44a7 {
  strings:
    $key_44a7 = { 13 d5 [2] 21 f7 [2] 27 c2 [2] 09 c2 [2] 36 de }

  condition:
    any of them
}