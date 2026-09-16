rule TTP_XOR_WriteProcessMemory_e176 {
  strings:
    $key_e176 = { b6 04 [2] 84 26 [2] 82 13 [2] ac 13 [2] 93 0f }

  condition:
    any of them
}