rule TTP_XOR_WriteProcessMemory_a6be {
  strings:
    $key_a6be = { f1 cc [2] c3 ee [2] c5 db [2] eb db [2] d4 c7 }

  condition:
    any of them
}