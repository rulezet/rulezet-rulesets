rule TTP_XOR_WriteProcessMemory_0db3 {
  strings:
    $key_0db3 = { 5a c1 [2] 68 e3 [2] 6e d6 [2] 40 d6 [2] 7f ca }

  condition:
    any of them
}