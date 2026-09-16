rule TTP_XOR_WriteProcessMemory_e88c {
  strings:
    $key_e88c = { bf fe [2] 8d dc [2] 8b e9 [2] a5 e9 [2] 9a f5 }

  condition:
    any of them
}