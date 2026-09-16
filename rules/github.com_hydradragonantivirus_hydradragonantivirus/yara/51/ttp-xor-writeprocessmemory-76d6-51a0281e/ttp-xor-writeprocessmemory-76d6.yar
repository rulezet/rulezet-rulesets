rule TTP_XOR_WriteProcessMemory_76d6 {
  strings:
    $key_76d6 = { 21 a4 [2] 13 86 [2] 15 b3 [2] 3b b3 [2] 04 af }

  condition:
    any of them
}