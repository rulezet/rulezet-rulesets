rule TTP_XOR_WriteProcessMemory_971c {
  strings:
    $key_971c = { c0 6e [2] f2 4c [2] f4 79 [2] da 79 [2] e5 65 }

  condition:
    any of them
}