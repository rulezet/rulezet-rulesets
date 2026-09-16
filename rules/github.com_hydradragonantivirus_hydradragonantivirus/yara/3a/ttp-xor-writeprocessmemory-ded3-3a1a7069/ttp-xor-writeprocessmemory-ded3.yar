rule TTP_XOR_WriteProcessMemory_ded3 {
  strings:
    $key_ded3 = { 89 a1 [2] bb 83 [2] bd b6 [2] 93 b6 [2] ac aa }

  condition:
    any of them
}