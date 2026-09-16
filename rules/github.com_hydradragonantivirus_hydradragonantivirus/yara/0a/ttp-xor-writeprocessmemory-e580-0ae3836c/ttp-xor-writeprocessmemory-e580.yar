rule TTP_XOR_WriteProcessMemory_e580 {
  strings:
    $key_e580 = { b2 f2 [2] 80 d0 [2] 86 e5 [2] a8 e5 [2] 97 f9 }

  condition:
    any of them
}