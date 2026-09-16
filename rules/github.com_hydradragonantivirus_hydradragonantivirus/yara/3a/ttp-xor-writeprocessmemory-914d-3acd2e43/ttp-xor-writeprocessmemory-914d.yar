rule TTP_XOR_WriteProcessMemory_914d {
  strings:
    $key_914d = { c6 3f [2] f4 1d [2] f2 28 [2] dc 28 [2] e3 34 }

  condition:
    any of them
}