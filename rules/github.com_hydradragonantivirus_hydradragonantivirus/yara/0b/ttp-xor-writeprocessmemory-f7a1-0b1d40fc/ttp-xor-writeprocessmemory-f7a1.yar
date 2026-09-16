rule TTP_XOR_WriteProcessMemory_f7a1 {
  strings:
    $key_f7a1 = { a0 d3 [2] 92 f1 [2] 94 c4 [2] ba c4 [2] 85 d8 }

  condition:
    any of them
}