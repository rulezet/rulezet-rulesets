rule TTP_XOR_WriteProcessMemory_7c9b {
  strings:
    $key_7c9b = { 2b e9 [2] 19 cb [2] 1f fe [2] 31 fe [2] 0e e2 }

  condition:
    any of them
}