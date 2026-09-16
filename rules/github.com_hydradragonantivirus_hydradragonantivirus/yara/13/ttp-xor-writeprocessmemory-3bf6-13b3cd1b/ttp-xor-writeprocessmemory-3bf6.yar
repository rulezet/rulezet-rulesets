rule TTP_XOR_WriteProcessMemory_3bf6 {
  strings:
    $key_3bf6 = { 6c 84 [2] 5e a6 [2] 58 93 [2] 76 93 [2] 49 8f }

  condition:
    any of them
}