rule TTP_XOR_WriteProcessMemory_3689 {
  strings:
    $key_3689 = { 61 fb [2] 53 d9 [2] 55 ec [2] 7b ec [2] 44 f0 }

  condition:
    any of them
}