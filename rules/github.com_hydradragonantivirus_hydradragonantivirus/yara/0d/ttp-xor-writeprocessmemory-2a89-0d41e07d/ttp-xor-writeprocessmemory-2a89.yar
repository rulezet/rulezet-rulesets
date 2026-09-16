rule TTP_XOR_WriteProcessMemory_2a89 {
  strings:
    $key_2a89 = { 7d fb [2] 4f d9 [2] 49 ec [2] 67 ec [2] 58 f0 }

  condition:
    any of them
}