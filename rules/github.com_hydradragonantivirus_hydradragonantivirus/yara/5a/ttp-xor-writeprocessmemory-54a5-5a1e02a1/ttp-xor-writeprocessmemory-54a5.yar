rule TTP_XOR_WriteProcessMemory_54a5 {
  strings:
    $key_54a5 = { 03 d7 [2] 31 f5 [2] 37 c0 [2] 19 c0 [2] 26 dc }

  condition:
    any of them
}