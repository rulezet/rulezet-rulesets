rule TTP_XOR_WriteProcessMemory_8160 {
  strings:
    $key_8160 = { d6 12 [2] e4 30 [2] e2 05 [2] cc 05 [2] f3 19 }

  condition:
    any of them
}