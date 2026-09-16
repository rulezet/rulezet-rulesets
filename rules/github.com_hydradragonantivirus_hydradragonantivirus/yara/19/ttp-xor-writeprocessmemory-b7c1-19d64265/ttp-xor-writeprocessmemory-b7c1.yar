rule TTP_XOR_WriteProcessMemory_b7c1 {
  strings:
    $key_b7c1 = { e0 b3 [2] d2 91 [2] d4 a4 [2] fa a4 [2] c5 b8 }

  condition:
    any of them
}