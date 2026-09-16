rule TTP_XOR_WriteProcessMemory_e146 {
  strings:
    $key_e146 = { b6 34 [2] 84 16 [2] 82 23 [2] ac 23 [2] 93 3f }

  condition:
    any of them
}