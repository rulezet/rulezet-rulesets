rule TTP_XOR_WriteProcessMemory_d0a5 {
  strings:
    $key_d0a5 = { 87 d7 [2] b5 f5 [2] b3 c0 [2] 9d c0 [2] a2 dc }

  condition:
    any of them
}