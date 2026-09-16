rule TTP_XOR_WriteProcessMemory_1f8b {
  strings:
    $key_1f8b = { 48 f9 [2] 7a db [2] 7c ee [2] 52 ee [2] 6d f2 }

  condition:
    any of them
}