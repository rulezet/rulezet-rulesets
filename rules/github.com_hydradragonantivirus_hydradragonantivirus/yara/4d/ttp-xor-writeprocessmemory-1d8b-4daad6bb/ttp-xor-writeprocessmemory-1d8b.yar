rule TTP_XOR_WriteProcessMemory_1d8b {
  strings:
    $key_1d8b = { 4a f9 [2] 78 db [2] 7e ee [2] 50 ee [2] 6f f2 }

  condition:
    any of them
}