rule TTP_XOR_WriteProcessMemory_42be {
  strings:
    $key_42be = { 15 cc [2] 27 ee [2] 21 db [2] 0f db [2] 30 c7 }

  condition:
    any of them
}