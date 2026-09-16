rule TTP_XOR_WriteProcessMemory_e196 {
  strings:
    $key_e196 = { b6 e4 [2] 84 c6 [2] 82 f3 [2] ac f3 [2] 93 ef }

  condition:
    any of them
}