rule TTP_XOR_WriteProcessMemory_0f89 {
  strings:
    $key_0f89 = { 58 fb [2] 6a d9 [2] 6c ec [2] 42 ec [2] 7d f0 }

  condition:
    any of them
}