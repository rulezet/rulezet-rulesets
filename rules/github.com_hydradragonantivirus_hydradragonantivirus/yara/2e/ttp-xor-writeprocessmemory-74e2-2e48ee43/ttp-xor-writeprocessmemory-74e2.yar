rule TTP_XOR_WriteProcessMemory_74e2 {
  strings:
    $key_74e2 = { 23 90 [2] 11 b2 [2] 17 87 [2] 39 87 [2] 06 9b }

  condition:
    any of them
}