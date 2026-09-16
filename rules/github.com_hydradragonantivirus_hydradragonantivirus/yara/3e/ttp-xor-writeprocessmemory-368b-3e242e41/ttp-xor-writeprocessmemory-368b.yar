rule TTP_XOR_WriteProcessMemory_368b {
  strings:
    $key_368b = { 61 f9 [2] 53 db [2] 55 ee [2] 7b ee [2] 44 f2 }

  condition:
    any of them
}