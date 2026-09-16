rule TTP_XOR_WriteProcessMemory_6bd6 {
  strings:
    $key_6bd6 = { 3c a4 [2] 0e 86 [2] 08 b3 [2] 26 b3 [2] 19 af }

  condition:
    any of them
}