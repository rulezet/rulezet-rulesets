rule TTP_XOR_WriteProcessMemory_d597 {
  strings:
    $key_d597 = { 82 e5 [2] b0 c7 [2] b6 f2 [2] 98 f2 [2] a7 ee }

  condition:
    any of them
}