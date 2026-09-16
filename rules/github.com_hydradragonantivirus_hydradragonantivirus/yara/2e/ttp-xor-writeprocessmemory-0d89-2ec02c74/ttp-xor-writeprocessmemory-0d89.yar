rule TTP_XOR_WriteProcessMemory_0d89 {
  strings:
    $key_0d89 = { 5a fb [2] 68 d9 [2] 6e ec [2] 40 ec [2] 7f f0 }

  condition:
    any of them
}