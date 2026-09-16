rule TTP_XOR_WriteProcessMemory_e5a1 {
  strings:
    $key_e5a1 = { b2 d3 [2] 80 f1 [2] 86 c4 [2] a8 c4 [2] 97 d8 }

  condition:
    any of them
}