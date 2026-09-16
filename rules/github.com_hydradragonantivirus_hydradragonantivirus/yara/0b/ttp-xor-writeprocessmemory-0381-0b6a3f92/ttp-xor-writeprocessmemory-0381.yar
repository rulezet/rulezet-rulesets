rule TTP_XOR_WriteProcessMemory_0381 {
  strings:
    $key_0381 = { 54 f3 [2] 66 d1 [2] 60 e4 [2] 4e e4 [2] 71 f8 }

  condition:
    any of them
}