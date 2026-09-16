rule TTP_XOR_WriteProcessMemory_c1c1 {
  strings:
    $key_c1c1 = { 96 b3 [2] a4 91 [2] a2 a4 [2] 8c a4 [2] b3 b8 }

  condition:
    any of them
}