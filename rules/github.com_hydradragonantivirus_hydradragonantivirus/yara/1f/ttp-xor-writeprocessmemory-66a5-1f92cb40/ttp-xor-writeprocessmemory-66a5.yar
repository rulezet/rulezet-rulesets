rule TTP_XOR_WriteProcessMemory_66a5 {
  strings:
    $key_66a5 = { 31 d7 [2] 03 f5 [2] 05 c0 [2] 2b c0 [2] 14 dc }

  condition:
    any of them
}