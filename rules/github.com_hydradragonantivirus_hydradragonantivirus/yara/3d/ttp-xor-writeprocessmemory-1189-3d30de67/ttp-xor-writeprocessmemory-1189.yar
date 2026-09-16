rule TTP_XOR_WriteProcessMemory_1189 {
  strings:
    $key_1189 = { 46 fb [2] 74 d9 [2] 72 ec [2] 5c ec [2] 63 f0 }

  condition:
    any of them
}