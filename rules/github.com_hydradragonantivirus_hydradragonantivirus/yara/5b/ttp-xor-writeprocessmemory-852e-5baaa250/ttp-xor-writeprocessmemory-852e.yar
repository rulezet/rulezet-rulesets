rule TTP_XOR_WriteProcessMemory_852e {
  strings:
    $key_852e = { d2 5c [2] e0 7e [2] e6 4b [2] c8 4b [2] f7 57 }

  condition:
    any of them
}