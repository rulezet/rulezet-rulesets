rule TTP_XOR_WriteProcessMemory_b4be {
  strings:
    $key_b4be = { e3 cc [2] d1 ee [2] d7 db [2] f9 db [2] c6 c7 }

  condition:
    any of them
}