rule TTP_XOR_WriteProcessMemory_971d {
  strings:
    $key_971d = { c0 6f [2] f2 4d [2] f4 78 [2] da 78 [2] e5 64 }

  condition:
    any of them
}