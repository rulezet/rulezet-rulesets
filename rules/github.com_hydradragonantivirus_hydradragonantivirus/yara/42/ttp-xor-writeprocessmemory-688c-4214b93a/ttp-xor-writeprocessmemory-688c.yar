rule TTP_XOR_WriteProcessMemory_688c {
  strings:
    $key_688c = { 3f fe [2] 0d dc [2] 0b e9 [2] 25 e9 [2] 1a f5 }

  condition:
    any of them
}