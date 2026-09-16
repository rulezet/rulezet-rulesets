rule TTP_XOR_WriteProcessMemory_a5be {
  strings:
    $key_a5be = { f2 cc [2] c0 ee [2] c6 db [2] e8 db [2] d7 c7 }

  condition:
    any of them
}