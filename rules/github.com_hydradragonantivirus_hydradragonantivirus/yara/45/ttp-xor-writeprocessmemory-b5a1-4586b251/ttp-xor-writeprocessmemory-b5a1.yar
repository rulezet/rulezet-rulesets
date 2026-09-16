rule TTP_XOR_WriteProcessMemory_b5a1 {
  strings:
    $key_b5a1 = { e2 d3 [2] d0 f1 [2] d6 c4 [2] f8 c4 [2] c7 d8 }

  condition:
    any of them
}