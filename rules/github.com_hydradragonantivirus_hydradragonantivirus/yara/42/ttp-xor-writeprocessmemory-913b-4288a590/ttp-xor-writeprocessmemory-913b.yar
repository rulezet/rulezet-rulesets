rule TTP_XOR_WriteProcessMemory_913b {
  strings:
    $key_913b = { c6 49 [2] f4 6b [2] f2 5e [2] dc 5e [2] e3 42 }

  condition:
    any of them
}