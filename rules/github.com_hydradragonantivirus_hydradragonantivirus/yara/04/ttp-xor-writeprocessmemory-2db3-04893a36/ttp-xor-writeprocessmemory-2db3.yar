rule TTP_XOR_WriteProcessMemory_2db3 {
  strings:
    $key_2db3 = { 7a c1 [2] 48 e3 [2] 4e d6 [2] 60 d6 [2] 5f ca }

  condition:
    any of them
}