rule TTP_XOR_WriteProcessMemory_ec8c {
  strings:
    $key_ec8c = { bb fe [2] 89 dc [2] 8f e9 [2] a1 e9 [2] 9e f5 }

  condition:
    any of them
}