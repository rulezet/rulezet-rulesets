rule TTP_XOR_WriteProcessMemory_94be {
  strings:
    $key_94be = { c3 cc [2] f1 ee [2] f7 db [2] d9 db [2] e6 c7 }

  condition:
    any of them
}