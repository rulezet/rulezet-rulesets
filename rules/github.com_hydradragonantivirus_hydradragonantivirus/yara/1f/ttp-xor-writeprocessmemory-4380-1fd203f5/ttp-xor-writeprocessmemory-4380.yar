rule TTP_XOR_WriteProcessMemory_4380 {
  strings:
    $key_4380 = { 14 f2 [2] 26 d0 [2] 20 e5 [2] 0e e5 [2] 31 f9 }

  condition:
    any of them
}