rule TTP_XOR_WriteProcessMemory_a580 {
  strings:
    $key_a580 = { f2 f2 [2] c0 d0 [2] c6 e5 [2] e8 e5 [2] d7 f9 }

  condition:
    any of them
}