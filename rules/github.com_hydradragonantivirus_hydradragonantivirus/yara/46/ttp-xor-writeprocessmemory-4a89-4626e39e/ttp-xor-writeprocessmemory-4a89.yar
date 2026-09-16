rule TTP_XOR_WriteProcessMemory_4a89 {
  strings:
    $key_4a89 = { 1d fb [2] 2f d9 [2] 29 ec [2] 07 ec [2] 38 f0 }

  condition:
    any of them
}