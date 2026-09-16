rule TTP_XOR_WriteProcessMemory_c397 {
  strings:
    $key_c397 = { 94 e5 [2] a6 c7 [2] a0 f2 [2] 8e f2 [2] b1 ee }

  condition:
    any of them
}