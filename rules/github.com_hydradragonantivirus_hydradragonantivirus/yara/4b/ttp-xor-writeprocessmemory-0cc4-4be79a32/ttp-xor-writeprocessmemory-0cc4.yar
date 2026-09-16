rule TTP_XOR_WriteProcessMemory_0cc4 {
  strings:
    $key_0cc4 = { 5b b6 [2] 69 94 [2] 6f a1 [2] 41 a1 [2] 7e bd }

  condition:
    any of them
}