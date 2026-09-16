rule TTP_XOR_WriteProcessMemory_c2b3 {
  strings:
    $key_c2b3 = { 95 c1 [2] a7 e3 [2] a1 d6 [2] 8f d6 [2] b0 ca }

  condition:
    any of them
}