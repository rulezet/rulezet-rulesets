rule TTP_XOR_WriteProcessMemory_7bf6 {
  strings:
    $key_7bf6 = { 2c 84 [2] 1e a6 [2] 18 93 [2] 36 93 [2] 09 8f }

  condition:
    any of them
}