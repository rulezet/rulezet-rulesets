rule TTP_XOR_WriteProcessMemory_33a7 {
  strings:
    $key_33a7 = { 64 d5 [2] 56 f7 [2] 50 c2 [2] 7e c2 [2] 41 de }

  condition:
    any of them
}