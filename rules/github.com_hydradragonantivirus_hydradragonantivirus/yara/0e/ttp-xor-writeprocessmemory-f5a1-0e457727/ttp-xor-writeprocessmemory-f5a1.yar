rule TTP_XOR_WriteProcessMemory_f5a1 {
  strings:
    $key_f5a1 = { a2 d3 [2] 90 f1 [2] 96 c4 [2] b8 c4 [2] 87 d8 }

  condition:
    any of them
}