rule TTP_XOR_WriteProcessMemory_5cb9 {
  strings:
    $key_5cb9 = { 0b cb [2] 39 e9 [2] 3f dc [2] 11 dc [2] 2e c0 }

  condition:
    any of them
}