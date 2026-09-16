rule TTP_XOR_WriteProcessMemory_c350 {
  strings:
    $key_c350 = { 94 22 [2] a6 00 [2] a0 35 [2] 8e 35 [2] b1 29 }

  condition:
    any of them
}