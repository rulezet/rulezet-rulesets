rule TTP_XOR_WriteProcessMemory_6f89 {
  strings:
    $key_6f89 = { 38 fb [2] 0a d9 [2] 0c ec [2] 22 ec [2] 1d f0 }

  condition:
    any of them
}