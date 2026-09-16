rule TTP_XOR_WriteProcessMemory_813f {
  strings:
    $key_813f = { d6 4d [2] e4 6f [2] e2 5a [2] cc 5a [2] f3 46 }

  condition:
    any of them
}