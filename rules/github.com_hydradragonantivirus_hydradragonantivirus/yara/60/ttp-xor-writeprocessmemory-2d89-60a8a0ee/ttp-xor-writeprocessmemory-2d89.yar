rule TTP_XOR_WriteProcessMemory_2d89 {
  strings:
    $key_2d89 = { 7a fb [2] 48 d9 [2] 4e ec [2] 60 ec [2] 5f f0 }

  condition:
    any of them
}