rule TTP_XOR_WriteProcessMemory_74a5 {
  strings:
    $key_74a5 = { 23 d7 [2] 11 f5 [2] 17 c0 [2] 39 c0 [2] 06 dc }

  condition:
    any of them
}