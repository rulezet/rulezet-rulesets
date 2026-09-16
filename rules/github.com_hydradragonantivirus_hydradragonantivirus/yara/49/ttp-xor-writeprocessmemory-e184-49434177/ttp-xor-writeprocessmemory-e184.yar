rule TTP_XOR_WriteProcessMemory_e184 {
  strings:
    $key_e184 = { b6 f6 [2] 84 d4 [2] 82 e1 [2] ac e1 [2] 93 fd }

  condition:
    any of them
}