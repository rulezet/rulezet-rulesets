rule TTP_XOR_WriteProcessMemory_c291 {
  strings:
    $key_c291 = { 95 e3 [2] a7 c1 [2] a1 f4 [2] 8f f4 [2] b0 e8 }

  condition:
    any of them
}