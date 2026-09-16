rule TTP_XOR_WriteProcessMemory_c7c1 {
  strings:
    $key_c7c1 = { 90 b3 [2] a2 91 [2] a4 a4 [2] 8a a4 [2] b5 b8 }

  condition:
    any of them
}