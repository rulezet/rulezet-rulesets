rule TTP_XOR_WriteProcessMemory_c4d9 {
  strings:
    $key_c4d9 = { 93 ab [2] a1 89 [2] a7 bc [2] 89 bc [2] b6 a0 }

  condition:
    any of them
}