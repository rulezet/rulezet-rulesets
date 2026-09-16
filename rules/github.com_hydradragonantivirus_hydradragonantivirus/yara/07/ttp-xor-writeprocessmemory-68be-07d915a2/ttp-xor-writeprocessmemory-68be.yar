rule TTP_XOR_WriteProcessMemory_68be {
  strings:
    $key_68be = { 3f cc [2] 0d ee [2] 0b db [2] 25 db [2] 1a c7 }

  condition:
    any of them
}