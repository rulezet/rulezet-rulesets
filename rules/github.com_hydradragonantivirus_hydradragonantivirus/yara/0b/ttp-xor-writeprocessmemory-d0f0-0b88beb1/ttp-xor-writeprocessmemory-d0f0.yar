rule TTP_XOR_WriteProcessMemory_d0f0 {
  strings:
    $key_d0f0 = { 87 82 [2] b5 a0 [2] b3 95 [2] 9d 95 [2] a2 89 }

  condition:
    any of them
}