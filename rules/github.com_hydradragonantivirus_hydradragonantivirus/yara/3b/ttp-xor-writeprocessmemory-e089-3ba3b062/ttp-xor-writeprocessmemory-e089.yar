rule TTP_XOR_WriteProcessMemory_e089 {
  strings:
    $key_e089 = { b7 fb [2] 85 d9 [2] 83 ec [2] ad ec [2] 92 f0 }

  condition:
    any of them
}