rule TTP_XOR_WriteProcessMemory_3096 {
  strings:
    $key_3096 = { 67 e4 [2] 55 c6 [2] 53 f3 [2] 7d f3 [2] 42 ef }

  condition:
    any of them
}