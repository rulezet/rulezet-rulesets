rule TTP_XOR_WriteProcessMemory_c180 {
  strings:
    $key_c180 = { 96 f2 [2] a4 d0 [2] a2 e5 [2] 8c e5 [2] b3 f9 }

  condition:
    any of them
}