rule TTP_XOR_WriteProcessMemory_4180 {
  strings:
    $key_4180 = { 16 f2 [2] 24 d0 [2] 22 e5 [2] 0c e5 [2] 33 f9 }

  condition:
    any of them
}