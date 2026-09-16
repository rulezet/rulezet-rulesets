rule TTP_XOR_WriteProcessMemory_e6f6 {
  strings:
    $key_e6f6 = { b1 84 [2] 83 a6 [2] 85 93 [2] ab 93 [2] 94 8f }

  condition:
    any of them
}