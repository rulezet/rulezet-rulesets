rule TTP_XOR_WriteProcessMemory_03a0 {
  strings:
    $key_03a0 = { 54 d2 [2] 66 f0 [2] 60 c5 [2] 4e c5 [2] 71 d9 }

  condition:
    any of them
}