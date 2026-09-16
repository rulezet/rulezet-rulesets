rule TTP_XOR_WriteProcessMemory_4cc4 {
  strings:
    $key_4cc4 = { 1b b6 [2] 29 94 [2] 2f a1 [2] 01 a1 [2] 3e bd }

  condition:
    any of them
}