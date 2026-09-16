rule TTP_XOR_WriteProcessMemory_47d6 {
  strings:
    $key_47d6 = { 10 a4 [2] 22 86 [2] 24 b3 [2] 0a b3 [2] 35 af }

  condition:
    any of them
}