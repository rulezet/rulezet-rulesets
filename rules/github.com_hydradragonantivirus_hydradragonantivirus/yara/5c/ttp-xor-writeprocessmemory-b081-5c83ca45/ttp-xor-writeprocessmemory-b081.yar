rule TTP_XOR_WriteProcessMemory_b081 {
  strings:
    $key_b081 = { e7 f3 [2] d5 d1 [2] d3 e4 [2] fd e4 [2] c2 f8 }

  condition:
    any of them
}