rule TTP_XOR_WriteProcessMemory_0bf6 {
  strings:
    $key_0bf6 = { 5c 84 [2] 6e a6 [2] 68 93 [2] 46 93 [2] 79 8f }

  condition:
    any of them
}