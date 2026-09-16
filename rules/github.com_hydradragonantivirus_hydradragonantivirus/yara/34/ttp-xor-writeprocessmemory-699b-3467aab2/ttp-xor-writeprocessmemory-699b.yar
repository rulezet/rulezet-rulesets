rule TTP_XOR_WriteProcessMemory_699b {
  strings:
    $key_699b = { 3e e9 [2] 0c cb [2] 0a fe [2] 24 fe [2] 1b e2 }

  condition:
    any of them
}