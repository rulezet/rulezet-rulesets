rule TTP_XOR_WriteProcessMemory_799b {
  strings:
    $key_799b = { 2e e9 [2] 1c cb [2] 1a fe [2] 34 fe [2] 0b e2 }

  condition:
    any of them
}