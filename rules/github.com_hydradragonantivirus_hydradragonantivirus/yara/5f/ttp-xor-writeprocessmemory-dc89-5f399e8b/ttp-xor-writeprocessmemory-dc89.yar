rule TTP_XOR_WriteProcessMemory_dc89 {
  strings:
    $key_dc89 = { 8b fb [2] b9 d9 [2] bf ec [2] 91 ec [2] ae f0 }

  condition:
    any of them
}