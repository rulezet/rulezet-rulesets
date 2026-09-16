rule TTP_XOR_WriteProcessMemory_e177 {
  strings:
    $key_e177 = { b6 05 [2] 84 27 [2] 82 12 [2] ac 12 [2] 93 0e }

  condition:
    any of them
}