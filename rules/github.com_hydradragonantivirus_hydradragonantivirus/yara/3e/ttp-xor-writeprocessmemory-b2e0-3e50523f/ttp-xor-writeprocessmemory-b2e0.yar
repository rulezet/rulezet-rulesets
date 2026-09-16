rule TTP_XOR_WriteProcessMemory_b2e0 {
  strings:
    $key_b2e0 = { e5 92 [2] d7 b0 [2] d1 85 [2] ff 85 [2] c0 99 }

  condition:
    any of them
}