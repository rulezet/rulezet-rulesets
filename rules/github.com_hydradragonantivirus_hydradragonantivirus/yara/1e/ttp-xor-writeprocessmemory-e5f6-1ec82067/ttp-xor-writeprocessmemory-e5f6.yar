rule TTP_XOR_WriteProcessMemory_e5f6 {
  strings:
    $key_e5f6 = { b2 84 [2] 80 a6 [2] 86 93 [2] a8 93 [2] 97 8f }

  condition:
    any of them
}