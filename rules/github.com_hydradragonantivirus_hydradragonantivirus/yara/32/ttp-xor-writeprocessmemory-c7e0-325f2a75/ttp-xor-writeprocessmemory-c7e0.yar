rule TTP_XOR_WriteProcessMemory_c7e0 {
  strings:
    $key_c7e0 = { 90 92 [2] a2 b0 [2] a4 85 [2] 8a 85 [2] b5 99 }

  condition:
    any of them
}