rule TTP_XOR_WriteProcessMemory_912b {
  strings:
    $key_912b = { c6 59 [2] f4 7b [2] f2 4e [2] dc 4e [2] e3 52 }

  condition:
    any of them
}