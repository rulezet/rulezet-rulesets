rule TTP_XOR_WriteProcessMemory_d596 {
  strings:
    $key_d596 = { 82 e4 [2] b0 c6 [2] b6 f3 [2] 98 f3 [2] a7 ef }

  condition:
    any of them
}