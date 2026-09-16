rule TTP_XOR_WriteProcessMemory_a3be {
  strings:
    $key_a3be = { f4 cc [2] c6 ee [2] c0 db [2] ee db [2] d1 c7 }

  condition:
    any of them
}