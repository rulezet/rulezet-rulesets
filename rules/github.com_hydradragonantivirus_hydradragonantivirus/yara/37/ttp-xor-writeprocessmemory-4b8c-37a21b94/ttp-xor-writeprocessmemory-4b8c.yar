rule TTP_XOR_WriteProcessMemory_4b8c {
  strings:
    $key_4b8c = { 1c fe [2] 2e dc [2] 28 e9 [2] 06 e9 [2] 39 f5 }

  condition:
    any of them
}