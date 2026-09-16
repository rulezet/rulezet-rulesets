rule TTP_XOR_WriteProcessMemory_deb9 {
  strings:
    $key_deb9 = { 89 cb [2] bb e9 [2] bd dc [2] 93 dc [2] ac c0 }

  condition:
    any of them
}