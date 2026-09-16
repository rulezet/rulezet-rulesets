rule TTP_XOR_WriteProcessMemory_91bb {
  strings:
    $key_91bb = { c6 c9 [2] f4 eb [2] f2 de [2] dc de [2] e3 c2 }

  condition:
    any of them
}