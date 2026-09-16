rule TTP_XOR_WriteProcessMemory_2a8c {
  strings:
    $key_2a8c = { 7d fe [2] 4f dc [2] 49 e9 [2] 67 e9 [2] 58 f5 }

  condition:
    any of them
}