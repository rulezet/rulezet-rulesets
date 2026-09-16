rule TTP_XOR_WriteProcessMemory_c1b3 {
  strings:
    $key_c1b3 = { 96 c1 [2] a4 e3 [2] a2 d6 [2] 8c d6 [2] b3 ca }

  condition:
    any of them
}