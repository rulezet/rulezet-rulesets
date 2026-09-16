rule TTP_XOR_WriteProcessMemory_e1e2 {
  strings:
    $key_e1e2 = { b6 90 [2] 84 b2 [2] 82 87 [2] ac 87 [2] 93 9b }

  condition:
    any of them
}