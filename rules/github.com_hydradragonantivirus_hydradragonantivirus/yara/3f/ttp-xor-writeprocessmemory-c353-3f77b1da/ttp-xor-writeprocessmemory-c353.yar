rule TTP_XOR_WriteProcessMemory_c353 {
  strings:
    $key_c353 = { 94 21 [2] a6 03 [2] a0 36 [2] 8e 36 [2] b1 2a }

  condition:
    any of them
}