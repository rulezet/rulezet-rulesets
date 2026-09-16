rule TTP_XOR_WriteProcessMemory_5d8b {
  strings:
    $key_5d8b = { 0a f9 [2] 38 db [2] 3e ee [2] 10 ee [2] 2f f2 }

  condition:
    any of them
}