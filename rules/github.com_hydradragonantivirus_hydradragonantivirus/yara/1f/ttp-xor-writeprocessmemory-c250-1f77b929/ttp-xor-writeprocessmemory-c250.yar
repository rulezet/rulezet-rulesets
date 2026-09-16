rule TTP_XOR_WriteProcessMemory_c250 {
  strings:
    $key_c250 = { 95 22 [2] a7 00 [2] a1 35 [2] 8f 35 [2] b0 29 }

  condition:
    any of them
}