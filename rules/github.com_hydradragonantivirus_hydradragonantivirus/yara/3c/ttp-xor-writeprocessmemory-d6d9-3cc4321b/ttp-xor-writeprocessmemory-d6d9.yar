rule TTP_XOR_WriteProcessMemory_d6d9 {
  strings:
    $key_d6d9 = { 81 ab [2] b3 89 [2] b5 bc [2] 9b bc [2] a4 a0 }

  condition:
    any of them
}