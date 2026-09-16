rule TTP_XOR_WriteProcessMemory_7e8c {
  strings:
    $key_7e8c = { 29 fe [2] 1b dc [2] 1d e9 [2] 33 e9 [2] 0c f5 }

  condition:
    any of them
}