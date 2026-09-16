rule TTP_XOR_WriteProcessMemory_7f8b {
  strings:
    $key_7f8b = { 28 f9 [2] 1a db [2] 1c ee [2] 32 ee [2] 0d f2 }

  condition:
    any of them
}