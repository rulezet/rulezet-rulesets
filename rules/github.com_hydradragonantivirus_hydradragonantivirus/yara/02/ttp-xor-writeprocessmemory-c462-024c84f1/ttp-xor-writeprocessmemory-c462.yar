rule TTP_XOR_WriteProcessMemory_c462 {
  strings:
    $key_c462 = { 93 10 [2] a1 32 [2] a7 07 [2] 89 07 [2] b6 1b }

  condition:
    any of them
}