rule TTP_XOR_WriteProcessMemory_859b {
  strings:
    $key_859b = { d2 e9 [2] e0 cb [2] e6 fe [2] c8 fe [2] f7 e2 }

  condition:
    any of them
}