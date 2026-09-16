rule TTP_XOR_WriteProcessMemory_3c8c {
  strings:
    $key_3c8c = { 6b fe [2] 59 dc [2] 5f e9 [2] 71 e9 [2] 4e f5 }

  condition:
    any of them
}