rule TTP_XOR_WriteProcessMemory_0c8c {
  strings:
    $key_0c8c = { 5b fe [2] 69 dc [2] 6f e9 [2] 41 e9 [2] 7e f5 }

  condition:
    any of them
}