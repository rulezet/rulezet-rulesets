rule TTP_XOR_WriteProcessMemory_c6e0 {
  strings:
    $key_c6e0 = { 91 92 [2] a3 b0 [2] a5 85 [2] 8b 85 [2] b4 99 }

  condition:
    any of them
}