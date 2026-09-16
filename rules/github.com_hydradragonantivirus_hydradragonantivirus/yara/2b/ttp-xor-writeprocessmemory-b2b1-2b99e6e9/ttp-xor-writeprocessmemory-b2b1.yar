rule TTP_XOR_WriteProcessMemory_b2b1 {
  strings:
    $key_b2b1 = { e5 c3 [2] d7 e1 [2] d1 d4 [2] ff d4 [2] c0 c8 }

  condition:
    any of them
}