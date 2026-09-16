rule TTP_XOR_WriteProcessMemory_b2a1 {
  strings:
    $key_b2a1 = { e5 d3 [2] d7 f1 [2] d1 c4 [2] ff c4 [2] c0 d8 }

  condition:
    any of them
}