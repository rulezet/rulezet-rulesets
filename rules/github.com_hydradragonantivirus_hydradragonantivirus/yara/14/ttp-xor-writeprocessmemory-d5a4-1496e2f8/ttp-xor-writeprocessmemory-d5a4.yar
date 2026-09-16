rule TTP_XOR_WriteProcessMemory_d5a4 {
  strings:
    $key_d5a4 = { 82 d6 [2] b0 f4 [2] b6 c1 [2] 98 c1 [2] a7 dd }

  condition:
    any of them
}