rule TTP_XOR_WriteProcessMemory_912c {
  strings:
    $key_912c = { c6 5e [2] f4 7c [2] f2 49 [2] dc 49 [2] e3 55 }

  condition:
    any of them
}