rule TTP_XOR_WriteProcessMemory_c332 {
  strings:
    $key_c332 = { 94 40 [2] a6 62 [2] a0 57 [2] 8e 57 [2] b1 4b }

  condition:
    any of them
}