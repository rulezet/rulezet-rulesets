rule TTP_XOR_WriteProcessMemory_909b {
  strings:
    $key_909b = { c7 e9 [2] f5 cb [2] f3 fe [2] dd fe [2] e2 e2 }

  condition:
    any of them
}