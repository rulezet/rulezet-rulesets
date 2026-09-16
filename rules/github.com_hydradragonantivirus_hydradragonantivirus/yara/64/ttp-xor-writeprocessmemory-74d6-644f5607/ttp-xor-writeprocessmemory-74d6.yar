rule TTP_XOR_WriteProcessMemory_74d6 {
  strings:
    $key_74d6 = { 23 a4 [2] 11 86 [2] 17 b3 [2] 39 b3 [2] 06 af }

  condition:
    any of them
}