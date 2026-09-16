rule TTP_XOR_WriteProcessMemory_4c9b {
  strings:
    $key_4c9b = { 1b e9 [2] 29 cb [2] 2f fe [2] 01 fe [2] 3e e2 }

  condition:
    any of them
}