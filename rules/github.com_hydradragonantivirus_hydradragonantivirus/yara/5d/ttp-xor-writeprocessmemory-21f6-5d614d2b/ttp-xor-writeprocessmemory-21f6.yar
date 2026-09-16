rule TTP_XOR_WriteProcessMemory_21f6 {
  strings:
    $key_21f6 = { 76 84 [2] 44 a6 [2] 42 93 [2] 6c 93 [2] 53 8f }

  condition:
    any of them
}