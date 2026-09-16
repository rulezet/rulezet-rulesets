rule TTP_XOR_WriteProcessMemory_3f8b {
  strings:
    $key_3f8b = { 68 f9 [2] 5a db [2] 5c ee [2] 72 ee [2] 4d f2 }

  condition:
    any of them
}