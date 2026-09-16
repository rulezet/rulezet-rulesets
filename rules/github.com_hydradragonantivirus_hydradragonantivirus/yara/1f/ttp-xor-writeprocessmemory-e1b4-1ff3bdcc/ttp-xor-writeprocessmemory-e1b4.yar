rule TTP_XOR_WriteProcessMemory_e1b4 {
  strings:
    $key_e1b4 = { b6 c6 [2] 84 e4 [2] 82 d1 [2] ac d1 [2] 93 cd }

  condition:
    any of them
}