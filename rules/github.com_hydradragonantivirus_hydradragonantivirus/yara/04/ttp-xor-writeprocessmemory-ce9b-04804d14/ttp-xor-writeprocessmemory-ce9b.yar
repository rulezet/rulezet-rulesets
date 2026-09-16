rule TTP_XOR_WriteProcessMemory_ce9b {
  strings:
    $key_ce9b = { 99 e9 [2] ab cb [2] ad fe [2] 83 fe [2] bc e2 }

  condition:
    any of them
}