rule TTP_XOR_WriteProcessMemory_40a5 {
  strings:
    $key_40a5 = { 17 d7 [2] 25 f5 [2] 23 c0 [2] 0d c0 [2] 32 dc }

  condition:
    any of them
}