rule TTP_XOR_WriteProcessMemory_975d {
  strings:
    $key_975d = { c0 2f [2] f2 0d [2] f4 38 [2] da 38 [2] e5 24 }

  condition:
    any of them
}