rule TTP_XOR_WriteProcessMemory_928b {
  strings:
    $key_928b = { c5 f9 [2] f7 db [2] f1 ee [2] df ee [2] e0 f2 }

  condition:
    any of them
}