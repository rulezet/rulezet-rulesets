rule TTP_XOR_WriteProcessMemory_c362 {
  strings:
    $key_c362 = { 94 10 [2] a6 32 [2] a0 07 [2] 8e 07 [2] b1 1b }

  condition:
    any of them
}