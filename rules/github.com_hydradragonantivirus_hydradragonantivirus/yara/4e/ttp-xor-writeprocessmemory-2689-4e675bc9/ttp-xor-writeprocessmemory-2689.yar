rule TTP_XOR_WriteProcessMemory_2689 {
  strings:
    $key_2689 = { 71 fb [2] 43 d9 [2] 45 ec [2] 6b ec [2] 54 f0 }

  condition:
    any of them
}