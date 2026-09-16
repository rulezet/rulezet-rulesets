rule TTP_XOR_WriteProcessMemory_36d6 {
  strings:
    $key_36d6 = { 61 a4 [2] 53 86 [2] 55 b3 [2] 7b b3 [2] 44 af }

  condition:
    any of them
}