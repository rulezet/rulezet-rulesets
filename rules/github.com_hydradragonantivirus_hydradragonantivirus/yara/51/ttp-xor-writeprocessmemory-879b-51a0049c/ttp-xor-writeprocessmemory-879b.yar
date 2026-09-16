rule TTP_XOR_WriteProcessMemory_879b {
  strings:
    $key_879b = { d0 e9 [2] e2 cb [2] e4 fe [2] ca fe [2] f5 e2 }

  condition:
    any of them
}