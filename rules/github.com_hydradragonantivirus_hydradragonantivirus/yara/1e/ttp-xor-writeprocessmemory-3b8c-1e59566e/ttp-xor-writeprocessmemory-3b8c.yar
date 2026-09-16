rule TTP_XOR_WriteProcessMemory_3b8c {
  strings:
    $key_3b8c = { 6c fe [2] 5e dc [2] 58 e9 [2] 76 e9 [2] 49 f5 }

  condition:
    any of them
}