rule TTP_XOR_WriteProcessMemory_251c {
  strings:
    $key_251c = { 72 6e [2] 40 4c [2] 46 79 [2] 68 79 [2] 57 65 }

  condition:
    any of them
}