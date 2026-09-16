rule TTP_XOR_WriteProcessMemory_f0be {
  strings:
    $key_f0be = { a7 cc [2] 95 ee [2] 93 db [2] bd db [2] 82 c7 }

  condition:
    any of them
}