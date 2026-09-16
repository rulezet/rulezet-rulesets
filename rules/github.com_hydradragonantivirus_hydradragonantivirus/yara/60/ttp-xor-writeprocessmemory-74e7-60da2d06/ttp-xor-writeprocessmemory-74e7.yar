rule TTP_XOR_WriteProcessMemory_74e7 {
  strings:
    $key_74e7 = { 23 95 [2] 11 b7 [2] 17 82 [2] 39 82 [2] 06 9e }

  condition:
    any of them
}