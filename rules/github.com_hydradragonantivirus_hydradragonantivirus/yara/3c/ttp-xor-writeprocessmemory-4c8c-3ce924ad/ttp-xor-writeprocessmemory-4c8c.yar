rule TTP_XOR_WriteProcessMemory_4c8c {
  strings:
    $key_4c8c = { 1b fe [2] 29 dc [2] 2f e9 [2] 01 e9 [2] 3e f5 }

  condition:
    any of them
}