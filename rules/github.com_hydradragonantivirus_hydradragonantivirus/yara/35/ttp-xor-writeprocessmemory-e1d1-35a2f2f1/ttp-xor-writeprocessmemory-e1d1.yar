rule TTP_XOR_WriteProcessMemory_e1d1 {
  strings:
    $key_e1d1 = { b6 a3 [2] 84 81 [2] 82 b4 [2] ac b4 [2] 93 a8 }

  condition:
    any of them
}