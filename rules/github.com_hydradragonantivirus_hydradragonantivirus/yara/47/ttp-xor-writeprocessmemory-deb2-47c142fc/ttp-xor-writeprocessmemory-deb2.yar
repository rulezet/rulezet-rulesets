rule TTP_XOR_WriteProcessMemory_deb2 {
  strings:
    $key_deb2 = { 89 c0 [2] bb e2 [2] bd d7 [2] 93 d7 [2] ac cb }

  condition:
    any of them
}