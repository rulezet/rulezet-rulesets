rule TTP_XOR_WriteProcessMemory_12be {
  strings:
    $key_12be = { 45 cc [2] 77 ee [2] 71 db [2] 5f db [2] 60 c7 }

  condition:
    any of them
}