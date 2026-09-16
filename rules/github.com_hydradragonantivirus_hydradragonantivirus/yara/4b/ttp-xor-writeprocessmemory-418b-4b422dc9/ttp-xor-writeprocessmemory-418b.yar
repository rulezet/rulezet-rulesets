rule TTP_XOR_WriteProcessMemory_418b {
  strings:
    $key_418b = { 16 f9 [2] 24 db [2] 22 ee [2] 0c ee [2] 33 f2 }

  condition:
    any of them
}