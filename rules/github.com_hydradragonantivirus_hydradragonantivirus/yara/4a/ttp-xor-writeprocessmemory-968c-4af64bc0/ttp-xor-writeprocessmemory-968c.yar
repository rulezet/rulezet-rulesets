rule TTP_XOR_WriteProcessMemory_968c {
  strings:
    $key_968c = { c1 fe [2] f3 dc [2] f5 e9 [2] db e9 [2] e4 f5 }

  condition:
    any of them
}