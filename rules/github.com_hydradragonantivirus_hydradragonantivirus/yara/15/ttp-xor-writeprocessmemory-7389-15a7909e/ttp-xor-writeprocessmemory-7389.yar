rule TTP_XOR_WriteProcessMemory_7389 {
  strings:
    $key_7389 = { 24 fb [2] 16 d9 [2] 10 ec [2] 3e ec [2] 01 f0 }

  condition:
    any of them
}