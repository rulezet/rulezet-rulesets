rule TTP_XOR_WriteProcessMemory_ded4 {
  strings:
    $key_ded4 = { 89 a6 [2] bb 84 [2] bd b1 [2] 93 b1 [2] ac ad }

  condition:
    any of them
}