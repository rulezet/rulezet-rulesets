rule TTP_XOR_WriteProcessMemory_f8a1 {
  strings:
    $key_f8a1 = { af d3 [2] 9d f1 [2] 9b c4 [2] b5 c4 [2] 8a d8 }

  condition:
    any of them
}