rule TTP_XOR_WriteProcessMemory_5bf6 {
  strings:
    $key_5bf6 = { 0c 84 [2] 3e a6 [2] 38 93 [2] 16 93 [2] 29 8f }

  condition:
    any of them
}