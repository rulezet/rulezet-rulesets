rule TTP_XOR_WriteProcessMemory_7f89 {
  strings:
    $key_7f89 = { 28 fb [2] 1a d9 [2] 1c ec [2] 32 ec [2] 0d f0 }

  condition:
    any of them
}