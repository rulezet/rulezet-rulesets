rule TTP_XOR_WriteProcessMemory_1bd6 {
  strings:
    $key_1bd6 = { 4c a4 [2] 7e 86 [2] 78 b3 [2] 56 b3 [2] 69 af }

  condition:
    any of them
}