rule TTP_XOR_WriteProcessMemory_8768 {
  strings:
    $key_8768 = { d0 1a [2] e2 38 [2] e4 0d [2] ca 0d [2] f5 11 }

  condition:
    any of them
}