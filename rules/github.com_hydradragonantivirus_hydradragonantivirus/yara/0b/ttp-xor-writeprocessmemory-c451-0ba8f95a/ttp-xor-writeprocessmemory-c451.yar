rule TTP_XOR_WriteProcessMemory_c451 {
  strings:
    $key_c451 = { 93 23 [2] a1 01 [2] a7 34 [2] 89 34 [2] b6 28 }

  condition:
    any of them
}