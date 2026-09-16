rule TTP_XOR_WriteProcessMemory_deb1 {
  strings:
    $key_deb1 = { 89 c3 [2] bb e1 [2] bd d4 [2] 93 d4 [2] ac c8 }

  condition:
    any of them
}