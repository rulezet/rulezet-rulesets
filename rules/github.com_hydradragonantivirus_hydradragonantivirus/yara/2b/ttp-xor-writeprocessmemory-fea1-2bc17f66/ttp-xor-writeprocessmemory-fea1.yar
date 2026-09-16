rule TTP_XOR_WriteProcessMemory_fea1 {
  strings:
    $key_fea1 = { a9 d3 [2] 9b f1 [2] 9d c4 [2] b3 c4 [2] 8c d8 }

  condition:
    any of them
}