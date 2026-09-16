rule TTP_XOR_WriteProcessMemory_937c {
  strings:
    $key_937c = { c4 0e [2] f6 2c [2] f0 19 [2] de 19 [2] e1 05 }

  condition:
    any of them
}