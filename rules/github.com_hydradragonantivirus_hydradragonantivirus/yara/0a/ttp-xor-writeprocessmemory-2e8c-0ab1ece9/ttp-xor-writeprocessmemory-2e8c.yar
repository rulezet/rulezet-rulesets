rule TTP_XOR_WriteProcessMemory_2e8c {
  strings:
    $key_2e8c = { 79 fe [2] 4b dc [2] 4d e9 [2] 63 e9 [2] 5c f5 }

  condition:
    any of them
}