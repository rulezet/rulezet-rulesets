rule TTP_XOR_WriteProcessMemory_6c9b {
  strings:
    $key_6c9b = { 3b e9 [2] 09 cb [2] 0f fe [2] 21 fe [2] 1e e2 }

  condition:
    any of them
}