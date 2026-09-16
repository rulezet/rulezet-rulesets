rule TTP_XOR_WriteProcessMemory_e132 {
  strings:
    $key_e132 = { b6 40 [2] 84 62 [2] 82 57 [2] ac 57 [2] 93 4b }

  condition:
    any of them
}