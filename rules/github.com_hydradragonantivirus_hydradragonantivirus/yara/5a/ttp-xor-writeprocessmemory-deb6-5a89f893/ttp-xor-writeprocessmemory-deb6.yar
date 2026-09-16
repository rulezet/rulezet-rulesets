rule TTP_XOR_WriteProcessMemory_deb6 {
  strings:
    $key_deb6 = { 89 c4 [2] bb e6 [2] bd d3 [2] 93 d3 [2] ac cf }

  condition:
    any of them
}