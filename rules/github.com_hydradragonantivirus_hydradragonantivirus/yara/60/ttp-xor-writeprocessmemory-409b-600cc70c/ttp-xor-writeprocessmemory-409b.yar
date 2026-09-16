rule TTP_XOR_WriteProcessMemory_409b {
  strings:
    $key_409b = { 17 e9 [2] 25 cb [2] 23 fe [2] 0d fe [2] 32 e2 }

  condition:
    any of them
}