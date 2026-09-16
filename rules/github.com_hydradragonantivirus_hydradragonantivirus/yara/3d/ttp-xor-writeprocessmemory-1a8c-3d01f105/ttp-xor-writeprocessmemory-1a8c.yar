rule TTP_XOR_WriteProcessMemory_1a8c {
  strings:
    $key_1a8c = { 4d fe [2] 7f dc [2] 79 e9 [2] 57 e9 [2] 68 f5 }

  condition:
    any of them
}