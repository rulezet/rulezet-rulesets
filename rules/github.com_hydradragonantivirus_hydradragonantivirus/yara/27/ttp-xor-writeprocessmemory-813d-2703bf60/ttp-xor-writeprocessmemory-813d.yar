rule TTP_XOR_WriteProcessMemory_813d {
  strings:
    $key_813d = { d6 4f [2] e4 6d [2] e2 58 [2] cc 58 [2] f3 44 }

  condition:
    any of them
}