rule TTP_XOR_WriteProcessMemory_c482 {
  strings:
    $key_c482 = { 93 f0 [2] a1 d2 [2] a7 e7 [2] 89 e7 [2] b6 fb }

  condition:
    any of them
}