rule TTP_XOR_WriteProcessMemory_65a5 {
  strings:
    $key_65a5 = { 32 d7 [2] 00 f5 [2] 06 c0 [2] 28 c0 [2] 17 dc }

  condition:
    any of them
}