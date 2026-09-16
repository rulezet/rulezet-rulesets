rule TTP_XOR_WriteProcessMemory_0096 {
  strings:
    $key_0096 = { 57 e4 [2] 65 c6 [2] 63 f3 [2] 4d f3 [2] 72 ef }

  condition:
    any of them
}