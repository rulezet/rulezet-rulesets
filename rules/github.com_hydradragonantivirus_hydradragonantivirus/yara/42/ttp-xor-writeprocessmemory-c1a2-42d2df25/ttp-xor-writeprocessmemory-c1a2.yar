rule TTP_XOR_WriteProcessMemory_c1a2 {
  strings:
    $key_c1a2 = { 96 d0 [2] a4 f2 [2] a2 c7 [2] 8c c7 [2] b3 db }

  condition:
    any of them
}