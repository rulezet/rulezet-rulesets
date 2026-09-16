rule TTP_XOR_WriteProcessMemory_c689 {
  strings:
    $key_c689 = { 91 fb [2] a3 d9 [2] a5 ec [2] 8b ec [2] b4 f0 }

  condition:
    any of them
}