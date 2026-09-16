rule TTP_XOR_WriteProcessMemory_5189 {
  strings:
    $key_5189 = { 06 fb [2] 34 d9 [2] 32 ec [2] 1c ec [2] 23 f0 }

  condition:
    any of them
}