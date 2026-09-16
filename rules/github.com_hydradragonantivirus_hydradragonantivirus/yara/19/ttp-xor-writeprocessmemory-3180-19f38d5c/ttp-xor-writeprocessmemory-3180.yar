rule TTP_XOR_WriteProcessMemory_3180 {
  strings:
    $key_3180 = { 66 f2 [2] 54 d0 [2] 52 e5 [2] 7c e5 [2] 43 f9 }

  condition:
    any of them
}