rule TTP_XOR_WriteProcessMemory_2f9b {
  strings:
    $key_2f9b = { 78 e9 [2] 4a cb [2] 4c fe [2] 62 fe [2] 5d e2 }

  condition:
    any of them
}