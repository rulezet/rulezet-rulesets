rule TTP_XOR_WriteProcessMemory_6689 {
  strings:
    $key_6689 = { 31 fb [2] 03 d9 [2] 05 ec [2] 2b ec [2] 14 f0 }

  condition:
    any of them
}