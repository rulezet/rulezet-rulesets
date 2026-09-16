rule TTP_XOR_WriteProcessMemory_1cc4 {
  strings:
    $key_1cc4 = { 4b b6 [2] 79 94 [2] 7f a1 [2] 51 a1 [2] 6e bd }

  condition:
    any of them
}