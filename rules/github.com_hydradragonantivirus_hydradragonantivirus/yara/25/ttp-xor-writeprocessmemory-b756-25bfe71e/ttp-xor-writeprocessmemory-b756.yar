rule TTP_XOR_WriteProcessMemory_b756 {
  strings:
    $key_b756 = { e0 24 [2] d2 06 [2] d4 33 [2] fa 33 [2] c5 2f }

  condition:
    any of them
}