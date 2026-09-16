rule TTP_XOR_WriteProcessMemory_c210 {
  strings:
    $key_c210 = { 95 62 [2] a7 40 [2] a1 75 [2] 8f 75 [2] b0 69 }

  condition:
    any of them
}