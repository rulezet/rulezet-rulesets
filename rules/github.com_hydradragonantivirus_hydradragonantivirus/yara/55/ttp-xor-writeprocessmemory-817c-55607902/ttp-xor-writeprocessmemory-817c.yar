rule TTP_XOR_WriteProcessMemory_817c {
  strings:
    $key_817c = { d6 0e [2] e4 2c [2] e2 19 [2] cc 19 [2] f3 05 }

  condition:
    any of them
}