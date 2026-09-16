rule TTP_XOR_WriteProcessMemory_f3a1 {
  strings:
    $key_f3a1 = { a4 d3 [2] 96 f1 [2] 90 c4 [2] be c4 [2] 81 d8 }

  condition:
    any of them
}