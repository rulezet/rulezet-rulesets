rule TTP_XOR_WriteProcessMemory_ff8b {
  strings:
    $key_ff8b = { a8 f9 [2] 9a db [2] 9c ee [2] b2 ee [2] 8d f2 }

  condition:
    any of them
}