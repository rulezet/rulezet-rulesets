rule TTP_XOR_WriteProcessMemory_819b {
  strings:
    $key_819b = { d6 e9 [2] e4 cb [2] e2 fe [2] cc fe [2] f3 e2 }

  condition:
    any of them
}