rule TTP_XOR_WriteProcessMemory_b7b0 {
  strings:
    $key_b7b0 = { e0 c2 [2] d2 e0 [2] d4 d5 [2] fa d5 [2] c5 c9 }

  condition:
    any of them
}