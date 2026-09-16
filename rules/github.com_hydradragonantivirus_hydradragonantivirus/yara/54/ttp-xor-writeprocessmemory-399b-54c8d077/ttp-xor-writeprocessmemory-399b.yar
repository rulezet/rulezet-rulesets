rule TTP_XOR_WriteProcessMemory_399b {
  strings:
    $key_399b = { 6e e9 [2] 5c cb [2] 5a fe [2] 74 fe [2] 4b e2 }

  condition:
    any of them
}