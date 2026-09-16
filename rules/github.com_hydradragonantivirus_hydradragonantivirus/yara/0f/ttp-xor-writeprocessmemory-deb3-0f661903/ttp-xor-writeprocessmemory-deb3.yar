rule TTP_XOR_WriteProcessMemory_deb3 {
  strings:
    $key_deb3 = { 89 c1 [2] bb e3 [2] bd d6 [2] 93 d6 [2] ac ca }

  condition:
    any of them
}