rule TTP_XOR_WriteProcessMemory_b7c4 {
  strings:
    $key_b7c4 = { e0 b6 [2] d2 94 [2] d4 a1 [2] fa a1 [2] c5 bd }

  condition:
    any of them
}