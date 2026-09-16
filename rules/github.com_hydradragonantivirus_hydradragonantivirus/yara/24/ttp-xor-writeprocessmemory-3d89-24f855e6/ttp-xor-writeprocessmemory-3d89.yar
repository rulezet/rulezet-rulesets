rule TTP_XOR_WriteProcessMemory_3d89 {
  strings:
    $key_3d89 = { 6a fb [2] 58 d9 [2] 5e ec [2] 70 ec [2] 4f f0 }

  condition:
    any of them
}