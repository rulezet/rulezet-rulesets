rule TTP_XOR_WriteProcessMemory_e5a7 {
  strings:
    $key_e5a7 = { b2 d5 [2] 80 f7 [2] 86 c2 [2] a8 c2 [2] 97 de }

  condition:
    any of them
}