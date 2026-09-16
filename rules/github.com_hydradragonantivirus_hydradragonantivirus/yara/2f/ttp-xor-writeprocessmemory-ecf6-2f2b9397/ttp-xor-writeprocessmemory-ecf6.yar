rule TTP_XOR_WriteProcessMemory_ecf6 {
  strings:
    $key_ecf6 = { bb 84 [2] 89 a6 [2] 8f 93 [2] a1 93 [2] 9e 8f }

  condition:
    any of them
}