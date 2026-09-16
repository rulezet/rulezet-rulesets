rule TTP_XOR_WriteProcessMemory_c1e2 {
  strings:
    $key_c1e2 = { 96 90 [2] a4 b2 [2] a2 87 [2] 8c 87 [2] b3 9b }

  condition:
    any of them
}