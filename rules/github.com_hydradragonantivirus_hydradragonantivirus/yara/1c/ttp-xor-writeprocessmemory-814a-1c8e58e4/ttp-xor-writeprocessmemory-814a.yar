rule TTP_XOR_WriteProcessMemory_814a {
  strings:
    $key_814a = { d6 38 [2] e4 1a [2] e2 2f [2] cc 2f [2] f3 33 }

  condition:
    any of them
}