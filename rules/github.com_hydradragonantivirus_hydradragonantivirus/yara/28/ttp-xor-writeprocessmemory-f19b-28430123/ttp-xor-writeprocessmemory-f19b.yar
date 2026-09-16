rule TTP_XOR_WriteProcessMemory_f19b {
  strings:
    $key_f19b = { a6 e9 [2] 94 cb [2] 92 fe [2] bc fe [2] 83 e2 }

  condition:
    any of them
}