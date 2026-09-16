rule TTP_XOR_WriteProcessMemory_528b {
  strings:
    $key_528b = { 05 f9 [2] 37 db [2] 31 ee [2] 1f ee [2] 20 f2 }

  condition:
    any of them
}