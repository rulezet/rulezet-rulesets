rule TTP_XOR_WriteProcessMemory_5180 {
  strings:
    $key_5180 = { 06 f2 [2] 34 d0 [2] 32 e5 [2] 1c e5 [2] 23 f9 }

  condition:
    any of them
}