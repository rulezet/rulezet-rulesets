rule TTP_XOR_WriteProcessMemory_7689 {
  strings:
    $key_7689 = { 21 fb [2] 13 d9 [2] 15 ec [2] 3b ec [2] 04 f0 }

  condition:
    any of them
}