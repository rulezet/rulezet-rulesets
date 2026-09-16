rule TTP_XOR_WriteProcessMemory_4089 {
  strings:
    $key_4089 = { 17 fb [2] 25 d9 [2] 23 ec [2] 0d ec [2] 32 f0 }

  condition:
    any of them
}