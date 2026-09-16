rule TTP_XOR_WriteProcessMemory_4d89 {
  strings:
    $key_4d89 = { 1a fb [2] 28 d9 [2] 2e ec [2] 00 ec [2] 3f f0 }

  condition:
    any of them
}