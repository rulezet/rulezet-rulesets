rule TTP_XOR_WriteProcessMemory_976c {
  strings:
    $key_976c = { c0 1e [2] f2 3c [2] f4 09 [2] da 09 [2] e5 15 }

  condition:
    any of them
}