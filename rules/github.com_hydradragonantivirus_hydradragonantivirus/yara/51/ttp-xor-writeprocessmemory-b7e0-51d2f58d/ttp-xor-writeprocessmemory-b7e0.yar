rule TTP_XOR_WriteProcessMemory_b7e0 {
  strings:
    $key_b7e0 = { e0 92 [2] d2 b0 [2] d4 85 [2] fa 85 [2] c5 99 }

  condition:
    any of them
}