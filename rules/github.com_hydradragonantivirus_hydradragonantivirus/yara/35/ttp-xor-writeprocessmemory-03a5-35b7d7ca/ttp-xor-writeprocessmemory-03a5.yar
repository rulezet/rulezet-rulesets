rule TTP_XOR_WriteProcessMemory_03a5 {
  strings:
    $key_03a5 = { 54 d7 [2] 66 f5 [2] 60 c0 [2] 4e c0 [2] 71 dc }

  condition:
    any of them
}