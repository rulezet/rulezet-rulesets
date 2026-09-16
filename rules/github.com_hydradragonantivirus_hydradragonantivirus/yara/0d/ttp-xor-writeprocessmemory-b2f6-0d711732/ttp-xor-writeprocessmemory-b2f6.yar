rule TTP_XOR_WriteProcessMemory_b2f6 {
  strings:
    $key_b2f6 = { e5 84 [2] d7 a6 [2] d1 93 [2] ff 93 [2] c0 8f }

  condition:
    any of them
}