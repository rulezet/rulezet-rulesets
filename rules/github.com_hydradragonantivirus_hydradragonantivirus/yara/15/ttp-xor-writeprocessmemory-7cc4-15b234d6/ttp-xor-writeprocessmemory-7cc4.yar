rule TTP_XOR_WriteProcessMemory_7cc4 {
  strings:
    $key_7cc4 = { 2b b6 [2] 19 94 [2] 1f a1 [2] 31 a1 [2] 0e bd }

  condition:
    any of them
}