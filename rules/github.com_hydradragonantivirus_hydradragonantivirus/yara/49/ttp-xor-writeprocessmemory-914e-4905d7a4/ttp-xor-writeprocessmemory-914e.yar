rule TTP_XOR_WriteProcessMemory_914e {
  strings:
    $key_914e = { c6 3c [2] f4 1e [2] f2 2b [2] dc 2b [2] e3 37 }

  condition:
    any of them
}