rule TTP_XOR_WriteProcessMemory_7d89 {
  strings:
    $key_7d89 = { 2a fb [2] 18 d9 [2] 1e ec [2] 30 ec [2] 0f f0 }

  condition:
    any of them
}