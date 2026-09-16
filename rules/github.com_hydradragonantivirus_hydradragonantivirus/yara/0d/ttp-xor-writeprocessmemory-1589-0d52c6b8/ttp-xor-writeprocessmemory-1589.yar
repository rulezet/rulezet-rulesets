rule TTP_XOR_WriteProcessMemory_1589 {
  strings:
    $key_1589 = { 42 fb [2] 70 d9 [2] 76 ec [2] 58 ec [2] 67 f0 }

  condition:
    any of them
}