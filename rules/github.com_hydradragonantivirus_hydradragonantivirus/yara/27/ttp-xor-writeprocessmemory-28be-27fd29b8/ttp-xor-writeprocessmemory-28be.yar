rule TTP_XOR_WriteProcessMemory_28be {
  strings:
    $key_28be = { 7f cc [2] 4d ee [2] 4b db [2] 65 db [2] 5a c7 }

  condition:
    any of them
}