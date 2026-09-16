rule TTP_XOR_WriteProcessMemory_179b {
  strings:
    $key_179b = { 40 e9 [2] 72 cb [2] 74 fe [2] 5a fe [2] 65 e2 }

  condition:
    any of them
}