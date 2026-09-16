rule TTP_XOR_WriteProcessMemory_915e {
  strings:
    $key_915e = { c6 2c [2] f4 0e [2] f2 3b [2] dc 3b [2] e3 27 }

  condition:
    any of them
}