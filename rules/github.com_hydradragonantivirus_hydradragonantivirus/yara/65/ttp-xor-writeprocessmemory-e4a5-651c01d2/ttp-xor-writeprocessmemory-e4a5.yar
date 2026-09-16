rule TTP_XOR_WriteProcessMemory_e4a5 {
  strings:
    $key_e4a5 = { b3 d7 [2] 81 f5 [2] 87 c0 [2] a9 c0 [2] 96 dc }

  condition:
    any of them
}