rule TTP_XOR_WriteProcessMemory_22a7 {
  strings:
    $key_22a7 = { 75 d5 [2] 47 f7 [2] 41 c2 [2] 6f c2 [2] 50 de }

  condition:
    any of them
}