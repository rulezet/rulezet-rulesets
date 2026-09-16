rule TTP_XOR_WriteProcessMemory_2380 {
  strings:
    $key_2380 = { 74 f2 [2] 46 d0 [2] 40 e5 [2] 6e e5 [2] 51 f9 }

  condition:
    any of them
}