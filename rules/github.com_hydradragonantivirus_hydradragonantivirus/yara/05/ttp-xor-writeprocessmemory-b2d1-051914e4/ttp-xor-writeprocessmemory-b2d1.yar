rule TTP_XOR_WriteProcessMemory_b2d1 {
  strings:
    $key_b2d1 = { e5 a3 [2] d7 81 [2] d1 b4 [2] ff b4 [2] c0 a8 }

  condition:
    any of them
}