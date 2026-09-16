rule TTP_XOR_WriteProcessMemory_1c8c {
  strings:
    $key_1c8c = { 4b fe [2] 79 dc [2] 7f e9 [2] 51 e9 [2] 6e f5 }

  condition:
    any of them
}