rule TTP_XOR_WriteProcessMemory_c7a5 {
  strings:
    $key_c7a5 = { 90 d7 [2] a2 f5 [2] a4 c0 [2] 8a c0 [2] b5 dc }

  condition:
    any of them
}