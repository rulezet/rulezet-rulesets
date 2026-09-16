rule TTP_XOR_WriteProcessMemory_1b8c {
  strings:
    $key_1b8c = { 4c fe [2] 7e dc [2] 78 e9 [2] 56 e9 [2] 69 f5 }

  condition:
    any of them
}