rule TTP_XOR_WriteProcessMemory_acb4 {
  strings:
    $key_acb4 = { fb c6 [2] c9 e4 [2] cf d1 [2] e1 d1 [2] de cd }

  condition:
    any of them
}