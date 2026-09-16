rule TTP_XOR_WriteProcessMemory_569b {
  strings:
    $key_569b = { 01 e9 [2] 33 cb [2] 35 fe [2] 1b fe [2] 24 e2 }

  condition:
    any of them
}