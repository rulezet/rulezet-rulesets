rule TTP_XOR_WriteProcessMemory_e1b0 {
  strings:
    $key_e1b0 = { b6 c2 [2] 84 e0 [2] 82 d5 [2] ac d5 [2] 93 c9 }

  condition:
    any of them
}