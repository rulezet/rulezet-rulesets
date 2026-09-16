rule TTP_XOR_WriteProcessMemory_c6d0 {
  strings:
    $key_c6d0 = { 91 a2 [2] a3 80 [2] a5 b5 [2] 8b b5 [2] b4 a9 }

  condition:
    any of them
}