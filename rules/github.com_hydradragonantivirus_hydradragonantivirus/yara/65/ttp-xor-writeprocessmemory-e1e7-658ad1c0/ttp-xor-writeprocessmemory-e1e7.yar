rule TTP_XOR_WriteProcessMemory_e1e7 {
  strings:
    $key_e1e7 = { b6 95 [2] 84 b7 [2] 82 82 [2] ac 82 [2] 93 9e }

  condition:
    any of them
}