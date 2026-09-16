rule TTP_XOR_WriteProcessMemory_5e9b {
  strings:
    $key_5e9b = { 09 e9 [2] 3b cb [2] 3d fe [2] 13 fe [2] 2c e2 }

  condition:
    any of them
}