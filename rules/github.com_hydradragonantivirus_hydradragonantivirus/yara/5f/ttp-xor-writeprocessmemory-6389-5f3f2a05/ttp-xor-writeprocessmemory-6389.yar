rule TTP_XOR_WriteProcessMemory_6389 {
  strings:
    $key_6389 = { 34 fb [2] 06 d9 [2] 00 ec [2] 2e ec [2] 11 f0 }

  condition:
    any of them
}