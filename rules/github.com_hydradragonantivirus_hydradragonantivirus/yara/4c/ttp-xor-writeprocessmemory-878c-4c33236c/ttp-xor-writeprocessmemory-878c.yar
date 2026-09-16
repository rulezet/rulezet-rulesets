rule TTP_XOR_WriteProcessMemory_878c {
  strings:
    $key_878c = { d0 fe [2] e2 dc [2] e4 e9 [2] ca e9 [2] f5 f5 }

  condition:
    any of them
}