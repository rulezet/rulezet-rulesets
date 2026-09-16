rule TTP_XOR_WriteProcessMemory_971e {
  strings:
    $key_971e = { c0 6c [2] f2 4e [2] f4 7b [2] da 7b [2] e5 67 }

  condition:
    any of them
}