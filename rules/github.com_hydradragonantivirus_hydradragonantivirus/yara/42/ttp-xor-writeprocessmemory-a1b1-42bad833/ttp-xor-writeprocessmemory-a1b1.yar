rule TTP_XOR_WriteProcessMemory_a1b1 {
  strings:
    $key_a1b1 = { f6 c3 [2] c4 e1 [2] c2 d4 [2] ec d4 [2] d3 c8 }

  condition:
    any of them
}