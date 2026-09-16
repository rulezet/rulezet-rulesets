rule TTP_XOR_WriteProcessMemory_d5d9 {
  strings:
    $key_d5d9 = { 82 ab [2] b0 89 [2] b6 bc [2] 98 bc [2] a7 a0 }

  condition:
    any of them
}