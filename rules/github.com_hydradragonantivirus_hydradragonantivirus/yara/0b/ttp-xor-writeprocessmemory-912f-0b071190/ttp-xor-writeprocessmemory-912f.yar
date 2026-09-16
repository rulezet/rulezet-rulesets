rule TTP_XOR_WriteProcessMemory_912f {
  strings:
    $key_912f = { c6 5d [2] f4 7f [2] f2 4a [2] dc 4a [2] e3 56 }

  condition:
    any of them
}