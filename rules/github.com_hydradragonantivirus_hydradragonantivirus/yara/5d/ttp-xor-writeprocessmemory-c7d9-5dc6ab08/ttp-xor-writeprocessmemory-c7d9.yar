rule TTP_XOR_WriteProcessMemory_c7d9 {
  strings:
    $key_c7d9 = { 90 ab [2] a2 89 [2] a4 bc [2] 8a bc [2] b5 a0 }

  condition:
    any of them
}