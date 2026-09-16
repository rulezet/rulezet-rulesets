rule TTP_XOR_WriteProcessMemory_811f {
  strings:
    $key_811f = { d6 6d [2] e4 4f [2] e2 7a [2] cc 7a [2] f3 66 }

  condition:
    any of them
}