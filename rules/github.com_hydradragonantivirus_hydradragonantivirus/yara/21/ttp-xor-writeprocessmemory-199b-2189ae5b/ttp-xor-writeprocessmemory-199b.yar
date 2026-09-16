rule TTP_XOR_WriteProcessMemory_199b {
  strings:
    $key_199b = { 4e e9 [2] 7c cb [2] 7a fe [2] 54 fe [2] 6b e2 }

  condition:
    any of them
}