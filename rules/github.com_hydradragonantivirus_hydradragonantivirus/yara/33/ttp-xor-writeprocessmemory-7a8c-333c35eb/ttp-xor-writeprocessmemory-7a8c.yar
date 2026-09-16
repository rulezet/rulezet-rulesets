rule TTP_XOR_WriteProcessMemory_7a8c {
  strings:
    $key_7a8c = { 2d fe [2] 1f dc [2] 19 e9 [2] 37 e9 [2] 08 f5 }

  condition:
    any of them
}