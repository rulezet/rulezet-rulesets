rule TTP_XOR_WriteProcessMemory_5db3 {
  strings:
    $key_5db3 = { 0a c1 [2] 38 e3 [2] 3e d6 [2] 10 d6 [2] 2f ca }

  condition:
    any of them
}