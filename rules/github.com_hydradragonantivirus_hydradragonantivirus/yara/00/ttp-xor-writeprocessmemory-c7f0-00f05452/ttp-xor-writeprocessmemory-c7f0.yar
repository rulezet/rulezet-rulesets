rule TTP_XOR_WriteProcessMemory_c7f0 {
  strings:
    $key_c7f0 = { 90 82 [2] a2 a0 [2] a4 95 [2] 8a 95 [2] b5 89 }

  condition:
    any of them
}