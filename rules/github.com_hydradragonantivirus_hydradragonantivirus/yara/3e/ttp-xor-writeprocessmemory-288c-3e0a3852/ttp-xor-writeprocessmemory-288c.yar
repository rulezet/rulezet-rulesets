rule TTP_XOR_WriteProcessMemory_288c {
  strings:
    $key_288c = { 7f fe [2] 4d dc [2] 4b e9 [2] 65 e9 [2] 5a f5 }

  condition:
    any of them
}