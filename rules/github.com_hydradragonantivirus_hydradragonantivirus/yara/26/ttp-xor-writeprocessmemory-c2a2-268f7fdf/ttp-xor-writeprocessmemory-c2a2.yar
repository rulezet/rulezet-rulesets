rule TTP_XOR_WriteProcessMemory_c2a2 {
  strings:
    $key_c2a2 = { 95 d0 [2] a7 f2 [2] a1 c7 [2] 8f c7 [2] b0 db }

  condition:
    any of them
}