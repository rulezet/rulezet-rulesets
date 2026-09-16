rule TTP_XOR_WriteProcessMemory_5089 {
  strings:
    $key_5089 = { 07 fb [2] 35 d9 [2] 33 ec [2] 1d ec [2] 22 f0 }

  condition:
    any of them
}