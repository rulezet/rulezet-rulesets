rule TTP_XOR_WriteProcessMemory_c280 {
  strings:
    $key_c280 = { 95 f2 [2] a7 d0 [2] a1 e5 [2] 8f e5 [2] b0 f9 }

  condition:
    any of them
}