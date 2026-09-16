rule TTP_XOR_WriteProcessMemory_468b {
  strings:
    $key_468b = { 11 f9 [2] 23 db [2] 25 ee [2] 0b ee [2] 34 f2 }

  condition:
    any of them
}