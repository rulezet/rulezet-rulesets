rule TTP_XOR_WriteProcessMemory_c373 {
  strings:
    $key_c373 = { 94 01 [2] a6 23 [2] a0 16 [2] 8e 16 [2] b1 0a }

  condition:
    any of them
}