rule TTP_XOR_WriteProcessMemory_e0f6 {
  strings:
    $key_e0f6 = { b7 84 [2] 85 a6 [2] 83 93 [2] ad 93 [2] 92 8f }

  condition:
    any of them
}