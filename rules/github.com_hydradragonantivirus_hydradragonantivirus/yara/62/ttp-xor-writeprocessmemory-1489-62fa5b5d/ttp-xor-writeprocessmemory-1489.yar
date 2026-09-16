rule TTP_XOR_WriteProcessMemory_1489 {
  strings:
    $key_1489 = { 43 fb [2] 71 d9 [2] 77 ec [2] 59 ec [2] 66 f0 }

  condition:
    any of them
}