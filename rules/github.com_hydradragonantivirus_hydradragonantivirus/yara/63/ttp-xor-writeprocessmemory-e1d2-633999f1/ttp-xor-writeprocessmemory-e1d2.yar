rule TTP_XOR_WriteProcessMemory_e1d2 {
  strings:
    $key_e1d2 = { b6 a0 [2] 84 82 [2] 82 b7 [2] ac b7 [2] 93 ab }

  condition:
    any of them
}