rule TTP_XOR_WriteProcessMemory_e167 {
  strings:
    $key_e167 = { b6 15 [2] 84 37 [2] 82 02 [2] ac 02 [2] 93 1e }

  condition:
    any of them
}