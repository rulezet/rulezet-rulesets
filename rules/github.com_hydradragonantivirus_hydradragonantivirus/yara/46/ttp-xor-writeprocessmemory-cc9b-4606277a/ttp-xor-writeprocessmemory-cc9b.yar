rule TTP_XOR_WriteProcessMemory_cc9b {
  strings:
    $key_cc9b = { 9b e9 [2] a9 cb [2] af fe [2] 81 fe [2] be e2 }

  condition:
    any of them
}