rule TTP_XOR_WriteProcessMemory_b5be {
  strings:
    $key_b5be = { e2 cc [2] d0 ee [2] d6 db [2] f8 db [2] c7 c7 }

  condition:
    any of them
}