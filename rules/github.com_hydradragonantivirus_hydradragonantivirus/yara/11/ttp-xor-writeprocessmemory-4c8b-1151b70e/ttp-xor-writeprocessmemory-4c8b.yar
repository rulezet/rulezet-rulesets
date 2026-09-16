rule TTP_XOR_WriteProcessMemory_4c8b {
  strings:
    $key_4c8b = { 1b f9 [2] 29 db [2] 2f ee [2] 01 ee [2] 3e f2 }

  condition:
    any of them
}