rule TTP_XOR_WriteProcessMemory_b7c5 {
  strings:
    $key_b7c5 = { e0 b7 [2] d2 95 [2] d4 a0 [2] fa a0 [2] c5 bc }

  condition:
    any of them
}