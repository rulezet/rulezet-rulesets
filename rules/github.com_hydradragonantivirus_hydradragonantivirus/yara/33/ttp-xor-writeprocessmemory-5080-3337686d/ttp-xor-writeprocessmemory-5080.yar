rule TTP_XOR_WriteProcessMemory_5080 {
  strings:
    $key_5080 = { 07 f2 [2] 35 d0 [2] 33 e5 [2] 1d e5 [2] 22 f9 }

  condition:
    any of them
}