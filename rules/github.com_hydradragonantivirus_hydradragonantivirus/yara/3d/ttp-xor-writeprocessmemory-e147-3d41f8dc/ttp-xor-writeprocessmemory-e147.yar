rule TTP_XOR_WriteProcessMemory_e147 {
  strings:
    $key_e147 = { b6 35 [2] 84 17 [2] 82 22 [2] ac 22 [2] 93 3e }

  condition:
    any of them
}