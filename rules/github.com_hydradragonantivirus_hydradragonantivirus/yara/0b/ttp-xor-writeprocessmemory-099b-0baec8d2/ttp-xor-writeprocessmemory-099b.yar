rule TTP_XOR_WriteProcessMemory_099b {
  strings:
    $key_099b = { 5e e9 [2] 6c cb [2] 6a fe [2] 44 fe [2] 7b e2 }

  condition:
    any of them
}