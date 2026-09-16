rule TTP_XOR_WriteProcessMemory_f0a7 {
  strings:
    $key_f0a7 = { a7 d5 [2] 95 f7 [2] 93 c2 [2] bd c2 [2] 82 de }

  condition:
    any of them
}