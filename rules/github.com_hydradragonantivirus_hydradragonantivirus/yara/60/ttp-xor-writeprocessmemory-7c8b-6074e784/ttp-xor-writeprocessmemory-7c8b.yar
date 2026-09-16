rule TTP_XOR_WriteProcessMemory_7c8b {
  strings:
    $key_7c8b = { 2b f9 [2] 19 db [2] 1f ee [2] 31 ee [2] 0e f2 }

  condition:
    any of them
}