rule TTP_XOR_WriteProcessMemory_912d {
  strings:
    $key_912d = { c6 5f [2] f4 7d [2] f2 48 [2] dc 48 [2] e3 54 }

  condition:
    any of them
}