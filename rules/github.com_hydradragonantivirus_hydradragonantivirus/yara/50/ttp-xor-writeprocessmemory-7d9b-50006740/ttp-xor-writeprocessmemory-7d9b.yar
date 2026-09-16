rule TTP_XOR_WriteProcessMemory_7d9b {
  strings:
    $key_7d9b = { 2a e9 [2] 18 cb [2] 1e fe [2] 30 fe [2] 0f e2 }

  condition:
    any of them
}