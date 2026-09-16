rule TTP_XOR_WriteProcessMemory_c0f0 {
  strings:
    $key_c0f0 = { 97 82 [2] a5 a0 [2] a3 95 [2] 8d 95 [2] b2 89 }

  condition:
    any of them
}