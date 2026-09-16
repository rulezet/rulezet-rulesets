rule TTP_XOR_WriteProcessMemory_f5be {
  strings:
    $key_f5be = { a2 cc [2] 90 ee [2] 96 db [2] b8 db [2] 87 c7 }

  condition:
    any of them
}