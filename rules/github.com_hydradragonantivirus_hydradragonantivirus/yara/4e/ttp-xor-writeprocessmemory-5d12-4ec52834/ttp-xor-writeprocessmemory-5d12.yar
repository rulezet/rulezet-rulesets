rule TTP_XOR_WriteProcessMemory_5d12 {
  strings:
    $key_5d12 = { 0a 60 [2] 38 42 [2] 3e 77 [2] 10 77 [2] 2f 6b }

  condition:
    any of them
}