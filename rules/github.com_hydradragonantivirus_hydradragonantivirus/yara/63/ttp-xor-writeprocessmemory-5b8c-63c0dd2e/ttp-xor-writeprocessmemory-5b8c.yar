rule TTP_XOR_WriteProcessMemory_5b8c {
  strings:
    $key_5b8c = { 0c fe [2] 3e dc [2] 38 e9 [2] 16 e9 [2] 29 f5 }

  condition:
    any of them
}