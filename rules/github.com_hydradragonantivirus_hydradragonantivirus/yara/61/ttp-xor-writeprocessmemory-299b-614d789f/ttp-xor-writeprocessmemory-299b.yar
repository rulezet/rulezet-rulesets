rule TTP_XOR_WriteProcessMemory_299b {
  strings:
    $key_299b = { 7e e9 [2] 4c cb [2] 4a fe [2] 64 fe [2] 5b e2 }

  condition:
    any of them
}