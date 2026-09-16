rule TTP_XOR_WriteProcessMemory_5f8b {
  strings:
    $key_5f8b = { 08 f9 [2] 3a db [2] 3c ee [2] 12 ee [2] 2d f2 }

  condition:
    any of them
}