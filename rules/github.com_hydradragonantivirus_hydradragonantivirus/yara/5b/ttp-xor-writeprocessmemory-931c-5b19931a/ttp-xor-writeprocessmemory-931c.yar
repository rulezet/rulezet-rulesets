rule TTP_XOR_WriteProcessMemory_931c {
  strings:
    $key_931c = { c4 6e [2] f6 4c [2] f0 79 [2] de 79 [2] e1 65 }

  condition:
    any of them
}