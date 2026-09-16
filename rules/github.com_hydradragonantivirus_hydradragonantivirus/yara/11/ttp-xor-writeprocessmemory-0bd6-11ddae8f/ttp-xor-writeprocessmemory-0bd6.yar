rule TTP_XOR_WriteProcessMemory_0bd6 {
  strings:
    $key_0bd6 = { 5c a4 [2] 6e 86 [2] 68 b3 [2] 46 b3 [2] 79 af }

  condition:
    any of them
}