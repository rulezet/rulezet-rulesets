rule TTP_XOR_WriteProcessMemory_c477 {
  strings:
    $key_c477 = { 93 05 [2] a1 27 [2] a7 12 [2] 89 12 [2] b6 0e }

  condition:
    any of them
}