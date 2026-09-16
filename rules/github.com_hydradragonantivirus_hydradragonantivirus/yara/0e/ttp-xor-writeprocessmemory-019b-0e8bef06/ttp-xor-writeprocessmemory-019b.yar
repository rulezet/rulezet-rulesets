rule TTP_XOR_WriteProcessMemory_019b {
  strings:
    $key_019b = { 56 e9 [2] 64 cb [2] 62 fe [2] 4c fe [2] 73 e2 }

  condition:
    any of them
}