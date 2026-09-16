rule TTP_XOR_WriteProcessMemory_c1d9 {
  strings:
    $key_c1d9 = { 96 ab [2] a4 89 [2] a2 bc [2] 8c bc [2] b3 a0 }

  condition:
    any of them
}