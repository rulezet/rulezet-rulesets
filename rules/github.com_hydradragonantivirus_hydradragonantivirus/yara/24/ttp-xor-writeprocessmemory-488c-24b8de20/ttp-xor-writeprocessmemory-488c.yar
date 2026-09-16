rule TTP_XOR_WriteProcessMemory_488c {
  strings:
    $key_488c = { 1f fe [2] 2d dc [2] 2b e9 [2] 05 e9 [2] 3a f5 }

  condition:
    any of them
}