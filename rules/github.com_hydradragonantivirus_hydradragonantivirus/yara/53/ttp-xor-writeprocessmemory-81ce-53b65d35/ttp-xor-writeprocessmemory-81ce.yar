rule TTP_XOR_WriteProcessMemory_81ce {
  strings:
    $key_81ce = { d6 bc [2] e4 9e [2] e2 ab [2] cc ab [2] f3 b7 }

  condition:
    any of them
}