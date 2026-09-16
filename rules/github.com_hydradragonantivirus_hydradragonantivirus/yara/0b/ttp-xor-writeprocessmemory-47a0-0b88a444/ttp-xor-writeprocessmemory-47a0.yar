rule TTP_XOR_WriteProcessMemory_47a0 {
  strings:
    $key_47a0 = { 10 d2 [2] 22 f0 [2] 24 c5 [2] 0a c5 [2] 35 d9 }

  condition:
    any of them
}