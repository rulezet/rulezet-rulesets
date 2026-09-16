rule TTP_XOR_WriteProcessMemory_e681 {
  strings:
    $key_e681 = { b1 f3 [2] 83 d1 [2] 85 e4 [2] ab e4 [2] 94 f8 }

  condition:
    any of them
}