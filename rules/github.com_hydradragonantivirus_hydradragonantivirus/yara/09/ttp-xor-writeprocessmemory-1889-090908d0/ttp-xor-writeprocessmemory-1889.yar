rule TTP_XOR_WriteProcessMemory_1889 {
  strings:
    $key_1889 = { 4f fb [2] 7d d9 [2] 7b ec [2] 55 ec [2] 6a f0 }

  condition:
    any of them
}