rule TTP_XOR_WriteProcessMemory_67d6 {
  strings:
    $key_67d6 = { 30 a4 [2] 02 86 [2] 04 b3 [2] 2a b3 [2] 15 af }

  condition:
    any of them
}