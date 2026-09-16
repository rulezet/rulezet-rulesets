rule TTP_XOR_WriteProcessMemory_ff89 {
  strings:
    $key_ff89 = { a8 fb [2] 9a d9 [2] 9c ec [2] b2 ec [2] 8d f0 }

  condition:
    any of them
}