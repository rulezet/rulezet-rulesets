rule TTP_XOR_WriteProcessMemory_b7e6 {
  strings:
    $key_b7e6 = { e0 94 [2] d2 b6 [2] d4 83 [2] fa 83 [2] c5 9f }

  condition:
    any of them
}