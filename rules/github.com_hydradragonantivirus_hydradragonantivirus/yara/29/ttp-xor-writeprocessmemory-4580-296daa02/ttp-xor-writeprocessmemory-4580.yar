rule TTP_XOR_WriteProcessMemory_4580 {
  strings:
    $key_4580 = { 12 f2 [2] 20 d0 [2] 26 e5 [2] 08 e5 [2] 37 f9 }

  condition:
    any of them
}