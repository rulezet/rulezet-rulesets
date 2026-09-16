rule TTP_XOR_WriteProcessMemory_8abe {
  strings:
    $key_8abe = { dd cc [2] ef ee [2] e9 db [2] c7 db [2] f8 c7 }

  condition:
    any of them
}