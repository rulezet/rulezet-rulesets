rule TTP_XOR_WriteProcessMemory_818c {
  strings:
    $key_818c = { d6 fe [2] e4 dc [2] e2 e9 [2] cc e9 [2] f3 f5 }

  condition:
    any of them
}