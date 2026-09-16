rule TTP_XOR_WriteProcessMemory_ea87 {
  strings:
    $key_ea87 = { bd f5 [2] 8f d7 [2] 89 e2 [2] a7 e2 [2] 98 fe }

  condition:
    any of them
}