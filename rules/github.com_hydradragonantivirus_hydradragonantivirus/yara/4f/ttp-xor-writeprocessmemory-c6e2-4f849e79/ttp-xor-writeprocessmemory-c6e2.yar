rule TTP_XOR_WriteProcessMemory_c6e2 {
  strings:
    $key_c6e2 = { 91 90 [2] a3 b2 [2] a5 87 [2] 8b 87 [2] b4 9b }

  condition:
    any of them
}