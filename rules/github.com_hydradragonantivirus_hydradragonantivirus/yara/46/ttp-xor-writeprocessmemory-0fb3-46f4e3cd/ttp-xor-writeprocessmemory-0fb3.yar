rule TTP_XOR_WriteProcessMemory_0fb3 {
  strings:
    $key_0fb3 = { 58 c1 [2] 6a e3 [2] 6c d6 [2] 42 d6 [2] 7d ca }

  condition:
    any of them
}