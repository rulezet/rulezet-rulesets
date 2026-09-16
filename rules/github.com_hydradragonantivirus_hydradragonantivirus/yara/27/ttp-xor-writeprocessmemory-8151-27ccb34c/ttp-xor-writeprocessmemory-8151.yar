rule TTP_XOR_WriteProcessMemory_8151 {
  strings:
    $key_8151 = { d6 23 [2] e4 01 [2] e2 34 [2] cc 34 [2] f3 28 }

  condition:
    any of them
}