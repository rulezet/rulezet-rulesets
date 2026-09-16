rule TTP_XOR_WriteProcessMemory_915b {
  strings:
    $key_915b = { c6 29 [2] f4 0b [2] f2 3e [2] dc 3e [2] e3 22 }

  condition:
    any of them
}