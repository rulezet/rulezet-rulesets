rule TTP_XOR_WriteProcessMemory_b898 {
  strings:
    $key_b898 = { ef ea [2] dd c8 [2] db fd [2] f5 fd [2] ca e1 }

  condition:
    any of them
}