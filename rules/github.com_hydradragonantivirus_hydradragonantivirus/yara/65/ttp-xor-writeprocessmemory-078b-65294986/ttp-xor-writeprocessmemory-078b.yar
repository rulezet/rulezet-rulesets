rule TTP_XOR_WriteProcessMemory_078b {
  strings:
    $key_078b = { 50 f9 [2] 62 db [2] 64 ee [2] 4a ee [2] 75 f2 }

  condition:
    any of them
}