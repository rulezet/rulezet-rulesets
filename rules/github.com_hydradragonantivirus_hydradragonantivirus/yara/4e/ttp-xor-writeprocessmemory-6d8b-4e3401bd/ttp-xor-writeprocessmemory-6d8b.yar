rule TTP_XOR_WriteProcessMemory_6d8b {
  strings:
    $key_6d8b = { 3a f9 [2] 08 db [2] 0e ee [2] 20 ee [2] 1f f2 }

  condition:
    any of them
}