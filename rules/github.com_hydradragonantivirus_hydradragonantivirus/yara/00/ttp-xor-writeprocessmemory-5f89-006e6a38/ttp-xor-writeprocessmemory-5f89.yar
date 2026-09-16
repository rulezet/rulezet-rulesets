rule TTP_XOR_WriteProcessMemory_5f89 {
  strings:
    $key_5f89 = { 08 fb [2] 3a d9 [2] 3c ec [2] 12 ec [2] 2d f0 }

  condition:
    any of them
}