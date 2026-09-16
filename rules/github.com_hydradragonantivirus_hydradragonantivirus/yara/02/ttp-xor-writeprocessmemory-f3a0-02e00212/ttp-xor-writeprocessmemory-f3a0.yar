rule TTP_XOR_WriteProcessMemory_f3a0 {
  strings:
    $key_f3a0 = { a4 d2 [2] 96 f0 [2] 90 c5 [2] be c5 [2] 81 d9 }

  condition:
    any of them
}