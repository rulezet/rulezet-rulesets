rule TTP_XOR_WriteProcessMemory_4df6 {
  strings:
    $key_4df6 = { 1a 84 [2] 28 a6 [2] 2e 93 [2] 00 93 [2] 3f 8f }

  condition:
    any of them
}