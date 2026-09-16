rule TTP_XOR_WriteProcessMemory_e29b {
  strings:
    $key_e29b = { b5 e9 [2] 87 cb [2] 81 fe [2] af fe [2] 90 e2 }

  condition:
    any of them
}