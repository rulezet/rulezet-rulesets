rule TTP_XOR_WriteProcessMemory_7789 {
  strings:
    $key_7789 = { 20 fb [2] 12 d9 [2] 14 ec [2] 3a ec [2] 05 f0 }

  condition:
    any of them
}