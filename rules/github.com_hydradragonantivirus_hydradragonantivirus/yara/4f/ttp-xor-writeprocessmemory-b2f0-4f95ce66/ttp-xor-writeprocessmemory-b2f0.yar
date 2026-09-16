rule TTP_XOR_WriteProcessMemory_b2f0 {
  strings:
    $key_b2f0 = { e5 82 [2] d7 a0 [2] d1 95 [2] ff 95 [2] c0 89 }

  condition:
    any of them
}