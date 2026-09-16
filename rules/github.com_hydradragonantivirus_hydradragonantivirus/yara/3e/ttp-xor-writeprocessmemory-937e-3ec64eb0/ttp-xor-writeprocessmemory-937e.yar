rule TTP_XOR_WriteProcessMemory_937e {
  strings:
    $key_937e = { c4 0c [2] f6 2e [2] f0 1b [2] de 1b [2] e1 07 }

  condition:
    any of them
}