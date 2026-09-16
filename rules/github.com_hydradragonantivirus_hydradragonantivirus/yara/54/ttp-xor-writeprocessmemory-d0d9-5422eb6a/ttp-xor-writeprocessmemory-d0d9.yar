rule TTP_XOR_WriteProcessMemory_d0d9 {
  strings:
    $key_d0d9 = { 87 ab [2] b5 89 [2] b3 bc [2] 9d bc [2] a2 a0 }

  condition:
    any of them
}