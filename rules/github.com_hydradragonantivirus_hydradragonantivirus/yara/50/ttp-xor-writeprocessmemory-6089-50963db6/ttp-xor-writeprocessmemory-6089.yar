rule TTP_XOR_WriteProcessMemory_6089 {
  strings:
    $key_6089 = { 37 fb [2] 05 d9 [2] 03 ec [2] 2d ec [2] 12 f0 }

  condition:
    any of them
}