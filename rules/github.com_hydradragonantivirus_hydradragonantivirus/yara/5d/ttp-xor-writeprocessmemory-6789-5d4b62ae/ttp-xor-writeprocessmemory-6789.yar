rule TTP_XOR_WriteProcessMemory_6789 {
  strings:
    $key_6789 = { 30 fb [2] 02 d9 [2] 04 ec [2] 2a ec [2] 15 f0 }

  condition:
    any of them
}