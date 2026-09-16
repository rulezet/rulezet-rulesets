rule TTP_XOR_WriteProcessMemory_b716 {
  strings:
    $key_b716 = { e0 64 [2] d2 46 [2] d4 73 [2] fa 73 [2] c5 6f }

  condition:
    any of them
}