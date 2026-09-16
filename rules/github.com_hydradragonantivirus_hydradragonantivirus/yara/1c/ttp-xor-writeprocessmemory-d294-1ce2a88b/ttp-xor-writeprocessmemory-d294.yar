rule TTP_XOR_WriteProcessMemory_d294 {
  strings:
    $key_d294 = { 85 e6 [2] b7 c4 [2] b1 f1 [2] 9f f1 [2] a0 ed }

  condition:
    any of them
}