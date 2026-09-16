rule TTP_XOR_WriteProcessMemory_d7a5 {
  strings:
    $key_d7a5 = { 80 d7 [2] b2 f5 [2] b4 c0 [2] 9a c0 [2] a5 dc }

  condition:
    any of them
}