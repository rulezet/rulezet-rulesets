rule TTP_XOR_WriteProcessMemory_848c {
  strings:
    $key_848c = { d3 fe [2] e1 dc [2] e7 e9 [2] c9 e9 [2] f6 f5 }

  condition:
    any of them
}