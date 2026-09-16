rule TTP_XOR_WriteProcessMemory_578b {
  strings:
    $key_578b = { 00 f9 [2] 32 db [2] 34 ee [2] 1a ee [2] 25 f2 }

  condition:
    any of them
}