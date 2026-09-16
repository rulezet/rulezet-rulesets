rule TTP_XOR_WriteProcessMemory_93d0 {
  strings:
    $key_93d0 = { c4 a2 [2] f6 80 [2] f0 b5 [2] de b5 [2] e1 a9 }

  condition:
    any of them
}