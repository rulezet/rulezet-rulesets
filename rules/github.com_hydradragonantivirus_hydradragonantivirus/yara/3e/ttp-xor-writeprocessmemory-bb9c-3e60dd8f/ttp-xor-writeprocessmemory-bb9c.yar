rule TTP_XOR_WriteProcessMemory_bb9c {
  strings:
    $key_bb9c = { ec ee [2] de cc [2] d8 f9 [2] f6 f9 [2] c9 e5 }

  condition:
    any of them
}