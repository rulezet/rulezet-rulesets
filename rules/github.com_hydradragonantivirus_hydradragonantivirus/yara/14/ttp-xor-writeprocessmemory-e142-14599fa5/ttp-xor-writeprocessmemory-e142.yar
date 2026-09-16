rule TTP_XOR_WriteProcessMemory_e142 {
  strings:
    $key_e142 = { b6 30 [2] 84 12 [2] 82 27 [2] ac 27 [2] 93 3b }

  condition:
    any of them
}