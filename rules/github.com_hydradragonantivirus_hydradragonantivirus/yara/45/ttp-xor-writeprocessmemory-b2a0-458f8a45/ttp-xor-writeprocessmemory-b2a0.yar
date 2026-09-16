rule TTP_XOR_WriteProcessMemory_b2a0 {
  strings:
    $key_b2a0 = { e5 d2 [2] d7 f0 [2] d1 c5 [2] ff c5 [2] c0 d9 }

  condition:
    any of them
}