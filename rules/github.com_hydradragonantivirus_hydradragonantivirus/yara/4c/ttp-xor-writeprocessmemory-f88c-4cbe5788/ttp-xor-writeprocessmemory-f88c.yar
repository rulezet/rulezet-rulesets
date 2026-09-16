rule TTP_XOR_WriteProcessMemory_f88c {
  strings:
    $key_f88c = { af fe [2] 9d dc [2] 9b e9 [2] b5 e9 [2] 8a f5 }

  condition:
    any of them
}