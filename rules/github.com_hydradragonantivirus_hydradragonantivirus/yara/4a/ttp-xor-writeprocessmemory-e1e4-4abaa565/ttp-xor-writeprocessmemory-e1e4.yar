rule TTP_XOR_WriteProcessMemory_e1e4 {
  strings:
    $key_e1e4 = { b6 96 [2] 84 b4 [2] 82 81 [2] ac 81 [2] 93 9d }

  condition:
    any of them
}