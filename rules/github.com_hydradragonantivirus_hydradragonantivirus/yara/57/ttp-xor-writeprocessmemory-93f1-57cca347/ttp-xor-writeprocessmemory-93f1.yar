rule TTP_XOR_WriteProcessMemory_93f1 {
  strings:
    $key_93f1 = { c4 83 [2] f6 a1 [2] f0 94 [2] de 94 [2] e1 88 }

  condition:
    any of them
}