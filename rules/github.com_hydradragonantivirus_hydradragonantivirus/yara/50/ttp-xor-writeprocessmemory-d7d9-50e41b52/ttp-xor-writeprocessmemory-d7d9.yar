rule TTP_XOR_WriteProcessMemory_d7d9 {
  strings:
    $key_d7d9 = { 80 ab [2] b2 89 [2] b4 bc [2] 9a bc [2] a5 a0 }

  condition:
    any of them
}