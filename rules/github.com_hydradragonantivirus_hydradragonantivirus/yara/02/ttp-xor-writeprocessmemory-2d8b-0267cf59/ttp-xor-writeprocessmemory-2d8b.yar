rule TTP_XOR_WriteProcessMemory_2d8b {
  strings:
    $key_2d8b = { 7a f9 [2] 48 db [2] 4e ee [2] 60 ee [2] 5f f2 }

  condition:
    any of them
}