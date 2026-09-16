rule TTP_XOR_WriteProcessMemory_c7a7 {
  strings:
    $key_c7a7 = { 90 d5 [2] a2 f7 [2] a4 c2 [2] 8a c2 [2] b5 de }

  condition:
    any of them
}