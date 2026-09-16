rule TTP_XOR_WriteProcessMemory_5389 {
  strings:
    $key_5389 = { 04 fb [2] 36 d9 [2] 30 ec [2] 1e ec [2] 21 f0 }

  condition:
    any of them
}