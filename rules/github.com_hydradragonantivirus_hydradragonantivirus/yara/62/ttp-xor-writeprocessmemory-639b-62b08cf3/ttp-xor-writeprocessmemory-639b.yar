rule TTP_XOR_WriteProcessMemory_639b {
  strings:
    $key_639b = { 34 e9 [2] 06 cb [2] 00 fe [2] 2e fe [2] 11 e2 }

  condition:
    any of them
}