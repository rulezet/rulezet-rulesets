rule TTP_XOR_WriteProcessMemory_3780 {
  strings:
    $key_3780 = { 60 f2 [2] 52 d0 [2] 54 e5 [2] 7a e5 [2] 45 f9 }

  condition:
    any of them
}