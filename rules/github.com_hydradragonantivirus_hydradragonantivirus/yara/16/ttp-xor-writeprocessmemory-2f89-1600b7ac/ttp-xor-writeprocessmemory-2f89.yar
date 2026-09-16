rule TTP_XOR_WriteProcessMemory_2f89 {
  strings:
    $key_2f89 = { 78 fb [2] 4a d9 [2] 4c ec [2] 62 ec [2] 5d f0 }

  condition:
    any of them
}