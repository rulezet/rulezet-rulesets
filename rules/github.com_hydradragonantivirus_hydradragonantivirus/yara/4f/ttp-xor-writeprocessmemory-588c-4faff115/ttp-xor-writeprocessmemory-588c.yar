rule TTP_XOR_WriteProcessMemory_588c {
  strings:
    $key_588c = { 0f fe [2] 3d dc [2] 3b e9 [2] 15 e9 [2] 2a f5 }

  condition:
    any of them
}