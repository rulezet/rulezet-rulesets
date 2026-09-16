rule TTP_XOR_WriteProcessMemory_8c89 {
  strings:
    $key_8c89 = { db fb [2] e9 d9 [2] ef ec [2] c1 ec [2] fe f0 }

  condition:
    any of them
}