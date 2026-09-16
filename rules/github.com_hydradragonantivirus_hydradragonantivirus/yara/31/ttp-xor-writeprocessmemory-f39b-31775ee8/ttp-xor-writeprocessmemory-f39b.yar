rule TTP_XOR_WriteProcessMemory_f39b {
  strings:
    $key_f39b = { a4 e9 [2] 96 cb [2] 90 fe [2] be fe [2] 81 e2 }

  condition:
    any of them
}