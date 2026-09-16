rule TTP_XOR_WriteProcessMemory_328b {
  strings:
    $key_328b = { 65 f9 [2] 57 db [2] 51 ee [2] 7f ee [2] 40 f2 }

  condition:
    any of them
}