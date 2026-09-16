rule TTP_XOR_WriteProcessMemory_d591 {
  strings:
    $key_d591 = { 82 e3 [2] b0 c1 [2] b6 f4 [2] 98 f4 [2] a7 e8 }

  condition:
    any of them
}