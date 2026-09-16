rule TTP_XOR_WriteProcessMemory_c2a7 {
  strings:
    $key_c2a7 = { 95 d5 [2] a7 f7 [2] a1 c2 [2] 8f c2 [2] b0 de }

  condition:
    any of them
}