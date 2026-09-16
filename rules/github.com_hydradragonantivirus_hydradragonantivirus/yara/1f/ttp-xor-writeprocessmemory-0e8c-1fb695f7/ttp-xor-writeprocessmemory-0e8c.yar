rule TTP_XOR_WriteProcessMemory_0e8c {
  strings:
    $key_0e8c = { 59 fe [2] 6b dc [2] 6d e9 [2] 43 e9 [2] 7c f5 }

  condition:
    any of them
}