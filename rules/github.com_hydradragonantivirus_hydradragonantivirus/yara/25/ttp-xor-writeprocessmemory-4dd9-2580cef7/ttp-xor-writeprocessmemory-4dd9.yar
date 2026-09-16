rule TTP_XOR_WriteProcessMemory_4dd9 {
  strings:
    $key_4dd9 = { 1a ab [2] 28 89 [2] 2e bc [2] 00 bc [2] 3f a0 }

  condition:
    any of them
}