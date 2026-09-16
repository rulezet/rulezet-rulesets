rule TTP_XOR_WriteProcessMemory_b291 {
  strings:
    $key_b291 = { e5 e3 [2] d7 c1 [2] d1 f4 [2] ff f4 [2] c0 e8 }

  condition:
    any of them
}