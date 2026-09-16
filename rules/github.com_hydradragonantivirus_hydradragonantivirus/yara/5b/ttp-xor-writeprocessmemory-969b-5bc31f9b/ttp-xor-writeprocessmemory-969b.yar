rule TTP_XOR_WriteProcessMemory_969b {
  strings:
    $key_969b = { c1 e9 [2] f3 cb [2] f5 fe [2] db fe [2] e4 e2 }

  condition:
    any of them
}