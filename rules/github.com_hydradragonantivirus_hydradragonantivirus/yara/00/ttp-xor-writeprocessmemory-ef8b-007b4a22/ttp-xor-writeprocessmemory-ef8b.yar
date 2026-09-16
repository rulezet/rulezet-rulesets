rule TTP_XOR_WriteProcessMemory_ef8b {
  strings:
    $key_ef8b = { b8 f9 [2] 8a db [2] 8c ee [2] a2 ee [2] 9d f2 }

  condition:
    any of them
}