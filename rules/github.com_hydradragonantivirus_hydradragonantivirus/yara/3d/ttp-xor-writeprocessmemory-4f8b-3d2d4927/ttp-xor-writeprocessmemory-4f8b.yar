rule TTP_XOR_WriteProcessMemory_4f8b {
  strings:
    $key_4f8b = { 18 f9 [2] 2a db [2] 2c ee [2] 02 ee [2] 3d f2 }

  condition:
    any of them
}