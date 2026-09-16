rule TTP_XOR_WriteProcessMemory_3089 {
  strings:
    $key_3089 = { 67 fb [2] 55 d9 [2] 53 ec [2] 7d ec [2] 42 f0 }

  condition:
    any of them
}