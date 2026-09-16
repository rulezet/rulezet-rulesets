rule TTP_XOR_WriteProcessMemory_d480 {
  strings:
    $key_d480 = { 83 f2 [2] b1 d0 [2] b7 e5 [2] 99 e5 [2] a6 f9 }

  condition:
    any of them
}