rule TTP_XOR_WriteProcessMemory_b781 {
  strings:
    $key_b781 = { e0 f3 [2] d2 d1 [2] d4 e4 [2] fa e4 [2] c5 f8 }

  condition:
    any of them
}