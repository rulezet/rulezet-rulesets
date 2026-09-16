rule TTP_XOR_WriteProcessMemory_1789 {
  strings:
    $key_1789 = { 40 fb [2] 72 d9 [2] 74 ec [2] 5a ec [2] 65 f0 }

  condition:
    any of them
}