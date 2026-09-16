rule TTP_XOR_WriteProcessMemory_23a5 {
  strings:
    $key_23a5 = { 74 d7 [2] 46 f5 [2] 40 c0 [2] 6e c0 [2] 51 dc }

  condition:
    any of them
}