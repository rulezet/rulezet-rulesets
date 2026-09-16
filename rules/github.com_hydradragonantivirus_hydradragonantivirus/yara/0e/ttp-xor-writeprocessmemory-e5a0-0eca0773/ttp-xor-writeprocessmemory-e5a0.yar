rule TTP_XOR_WriteProcessMemory_e5a0 {
  strings:
    $key_e5a0 = { b2 d2 [2] 80 f0 [2] 86 c5 [2] a8 c5 [2] 97 d9 }

  condition:
    any of them
}