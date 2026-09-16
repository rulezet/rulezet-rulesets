rule TTP_XOR_WriteProcessMemory_c6a7 {
  strings:
    $key_c6a7 = { 91 d5 [2] a3 f7 [2] a5 c2 [2] 8b c2 [2] b4 de }

  condition:
    any of them
}