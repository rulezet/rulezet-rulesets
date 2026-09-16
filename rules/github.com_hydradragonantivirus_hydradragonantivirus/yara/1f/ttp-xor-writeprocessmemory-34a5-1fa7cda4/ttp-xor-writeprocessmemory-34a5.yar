rule TTP_XOR_WriteProcessMemory_34a5 {
  strings:
    $key_34a5 = { 63 d7 [2] 51 f5 [2] 57 c0 [2] 79 c0 [2] 46 dc }

  condition:
    any of them
}