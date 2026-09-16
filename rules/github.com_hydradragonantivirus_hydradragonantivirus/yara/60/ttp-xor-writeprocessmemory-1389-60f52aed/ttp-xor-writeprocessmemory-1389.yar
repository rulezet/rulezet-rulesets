rule TTP_XOR_WriteProcessMemory_1389 {
  strings:
    $key_1389 = { 44 fb [2] 76 d9 [2] 70 ec [2] 5e ec [2] 61 f0 }

  condition:
    any of them
}