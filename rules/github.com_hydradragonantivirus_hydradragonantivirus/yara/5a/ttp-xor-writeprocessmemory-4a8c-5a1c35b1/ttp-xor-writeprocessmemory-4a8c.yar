rule TTP_XOR_WriteProcessMemory_4a8c {
  strings:
    $key_4a8c = { 1d fe [2] 2f dc [2] 29 e9 [2] 07 e9 [2] 38 f5 }

  condition:
    any of them
}