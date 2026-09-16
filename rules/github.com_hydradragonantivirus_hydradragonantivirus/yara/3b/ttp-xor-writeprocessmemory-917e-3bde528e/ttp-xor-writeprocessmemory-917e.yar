rule TTP_XOR_WriteProcessMemory_917e {
  strings:
    $key_917e = { c6 0c [2] f4 2e [2] f2 1b [2] dc 1b [2] e3 07 }

  condition:
    any of them
}