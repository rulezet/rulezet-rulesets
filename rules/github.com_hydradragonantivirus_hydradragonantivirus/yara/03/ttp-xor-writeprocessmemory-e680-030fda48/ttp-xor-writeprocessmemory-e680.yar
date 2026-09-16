rule TTP_XOR_WriteProcessMemory_e680 {
  strings:
    $key_e680 = { b1 f2 [2] 83 d0 [2] 85 e5 [2] ab e5 [2] 94 f9 }

  condition:
    any of them
}