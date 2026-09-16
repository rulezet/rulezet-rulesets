rule TTP_XOR_WriteProcessMemory_1cb9 {
  strings:
    $key_1cb9 = { 4b cb [2] 79 e9 [2] 7f dc [2] 51 dc [2] 6e c0 }

  condition:
    any of them
}