rule TTP_XOR_WriteProcessMemory_c400 {
  strings:
    $key_c400 = { 93 72 [2] a1 50 [2] a7 65 [2] 89 65 [2] b6 79 }

  condition:
    any of them
}