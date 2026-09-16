rule TTP_XOR_WriteProcessMemory_2596 {
  strings:
    $key_2596 = { 72 e4 [2] 40 c6 [2] 46 f3 [2] 68 f3 [2] 57 ef }

  condition:
    any of them
}