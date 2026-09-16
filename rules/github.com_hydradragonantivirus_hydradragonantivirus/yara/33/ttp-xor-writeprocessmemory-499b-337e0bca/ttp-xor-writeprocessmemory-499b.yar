rule TTP_XOR_WriteProcessMemory_499b {
  strings:
    $key_499b = { 1e e9 [2] 2c cb [2] 2a fe [2] 04 fe [2] 3b e2 }

  condition:
    any of them
}