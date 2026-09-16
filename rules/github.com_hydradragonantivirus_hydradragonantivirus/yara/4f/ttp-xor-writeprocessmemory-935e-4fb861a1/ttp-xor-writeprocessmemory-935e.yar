rule TTP_XOR_WriteProcessMemory_935e {
  strings:
    $key_935e = { c4 2c [2] f6 0e [2] f0 3b [2] de 3b [2] e1 27 }

  condition:
    any of them
}