rule TTP_XOR_WriteProcessMemory_ea82 {
  strings:
    $key_ea82 = { bd f0 [2] 8f d2 [2] 89 e7 [2] a7 e7 [2] 98 fb }

  condition:
    any of them
}