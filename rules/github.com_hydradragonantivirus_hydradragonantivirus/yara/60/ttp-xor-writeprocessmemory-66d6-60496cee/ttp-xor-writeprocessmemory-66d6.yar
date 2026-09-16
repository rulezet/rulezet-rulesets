rule TTP_XOR_WriteProcessMemory_66d6 {
  strings:
    $key_66d6 = { 31 a4 [2] 03 86 [2] 05 b3 [2] 2b b3 [2] 14 af }

  condition:
    any of them
}