rule TTP_XOR_WriteProcessMemory_26d6 {
  strings:
    $key_26d6 = { 71 a4 [2] 43 86 [2] 45 b3 [2] 6b b3 [2] 54 af }

  condition:
    any of them
}