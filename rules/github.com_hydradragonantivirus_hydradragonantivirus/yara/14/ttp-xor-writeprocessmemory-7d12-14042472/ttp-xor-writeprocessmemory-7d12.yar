rule TTP_XOR_WriteProcessMemory_7d12 {
  strings:
    $key_7d12 = { 2a 60 [2] 18 42 [2] 1e 77 [2] 30 77 [2] 0f 6b }

  condition:
    any of them
}