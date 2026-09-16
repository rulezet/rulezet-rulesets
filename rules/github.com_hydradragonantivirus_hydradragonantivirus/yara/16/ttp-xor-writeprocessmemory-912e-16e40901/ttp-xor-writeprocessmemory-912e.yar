rule TTP_XOR_WriteProcessMemory_912e {
  strings:
    $key_912e = { c6 5c [2] f4 7e [2] f2 4b [2] dc 4b [2] e3 57 }

  condition:
    any of them
}