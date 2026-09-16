rule TTP_XOR_WriteProcessMemory_939b {
  strings:
    $key_939b = { c4 e9 [2] f6 cb [2] f0 fe [2] de fe [2] e1 e2 }

  condition:
    any of them
}