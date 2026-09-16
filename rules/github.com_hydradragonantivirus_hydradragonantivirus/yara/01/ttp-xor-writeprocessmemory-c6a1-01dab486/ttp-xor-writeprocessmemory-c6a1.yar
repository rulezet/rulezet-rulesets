rule TTP_XOR_WriteProcessMemory_c6a1 {
  strings:
    $key_c6a1 = { 91 d3 [2] a3 f1 [2] a5 c4 [2] 8b c4 [2] b4 d8 }

  condition:
    any of them
}