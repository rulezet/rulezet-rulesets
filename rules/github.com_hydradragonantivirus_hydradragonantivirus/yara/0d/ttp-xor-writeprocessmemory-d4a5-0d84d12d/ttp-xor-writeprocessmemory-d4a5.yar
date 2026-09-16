rule TTP_XOR_WriteProcessMemory_d4a5 {
  strings:
    $key_d4a5 = { 83 d7 [2] b1 f5 [2] b7 c0 [2] 99 c0 [2] a6 dc }

  condition:
    any of them
}