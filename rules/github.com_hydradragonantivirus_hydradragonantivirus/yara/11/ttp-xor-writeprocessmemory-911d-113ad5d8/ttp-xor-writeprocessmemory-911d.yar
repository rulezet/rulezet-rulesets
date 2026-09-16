rule TTP_XOR_WriteProcessMemory_911d {
  strings:
    $key_911d = { c6 6f [2] f4 4d [2] f2 78 [2] dc 78 [2] e3 64 }

  condition:
    any of them
}