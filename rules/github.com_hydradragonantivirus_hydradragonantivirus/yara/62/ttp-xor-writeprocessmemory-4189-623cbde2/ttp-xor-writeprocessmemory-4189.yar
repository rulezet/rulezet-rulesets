rule TTP_XOR_WriteProcessMemory_4189 {
  strings:
    $key_4189 = { 16 fb [2] 24 d9 [2] 22 ec [2] 0c ec [2] 33 f0 }

  condition:
    any of them
}