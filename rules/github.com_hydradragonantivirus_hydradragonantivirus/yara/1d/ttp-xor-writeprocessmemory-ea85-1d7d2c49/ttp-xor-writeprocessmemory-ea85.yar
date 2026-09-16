rule TTP_XOR_WriteProcessMemory_ea85 {
  strings:
    $key_ea85 = { bd f7 [2] 8f d5 [2] 89 e0 [2] a7 e0 [2] 98 fc }

  condition:
    any of them
}