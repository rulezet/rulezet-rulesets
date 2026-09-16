rule TTP_XOR_WriteProcessMemory_3e9b {
  strings:
    $key_3e9b = { 69 e9 [2] 5b cb [2] 5d fe [2] 73 fe [2] 4c e2 }

  condition:
    any of them
}