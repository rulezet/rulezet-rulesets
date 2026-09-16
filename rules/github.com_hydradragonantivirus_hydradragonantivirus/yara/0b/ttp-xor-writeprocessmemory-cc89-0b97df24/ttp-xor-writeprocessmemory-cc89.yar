rule TTP_XOR_WriteProcessMemory_cc89 {
  strings:
    $key_cc89 = { 9b fb [2] a9 d9 [2] af ec [2] 81 ec [2] be f0 }

  condition:
    any of them
}