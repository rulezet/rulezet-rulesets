rule TTP_XOR_WriteProcessMemory_1c9b {
  strings:
    $key_1c9b = { 4b e9 [2] 79 cb [2] 7f fe [2] 51 fe [2] 6e e2 }

  condition:
    any of them
}