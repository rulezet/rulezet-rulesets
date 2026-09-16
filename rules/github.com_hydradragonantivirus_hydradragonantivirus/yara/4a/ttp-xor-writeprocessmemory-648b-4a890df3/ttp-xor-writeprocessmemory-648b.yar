rule TTP_XOR_WriteProcessMemory_648b {
  strings:
    $key_648b = { 33 f9 [2] 01 db [2] 07 ee [2] 29 ee [2] 16 f2 }

  condition:
    any of them
}