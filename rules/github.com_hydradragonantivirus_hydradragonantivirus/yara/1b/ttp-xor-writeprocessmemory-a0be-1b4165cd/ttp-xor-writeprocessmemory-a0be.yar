rule TTP_XOR_WriteProcessMemory_a0be {
  strings:
    $key_a0be = { f7 cc [2] c5 ee [2] c3 db [2] ed db [2] d2 c7 }

  condition:
    any of them
}