rule TTP_XOR_WriteProcessMemory_b726 {
  strings:
    $key_b726 = { e0 54 [2] d2 76 [2] d4 43 [2] fa 43 [2] c5 5f }

  condition:
    any of them
}