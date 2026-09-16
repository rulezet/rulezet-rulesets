rule TTP_XOR_WriteProcessMemory_6489 {
  strings:
    $key_6489 = { 33 fb [2] 01 d9 [2] 07 ec [2] 29 ec [2] 16 f0 }

  condition:
    any of them
}