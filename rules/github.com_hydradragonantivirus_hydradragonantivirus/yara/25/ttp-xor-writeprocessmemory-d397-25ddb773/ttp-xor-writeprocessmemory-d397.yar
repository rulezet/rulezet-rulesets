rule TTP_XOR_WriteProcessMemory_d397 {
  strings:
    $key_d397 = { 84 e5 [2] b6 c7 [2] b0 f2 [2] 9e f2 [2] a1 ee }

  condition:
    any of them
}