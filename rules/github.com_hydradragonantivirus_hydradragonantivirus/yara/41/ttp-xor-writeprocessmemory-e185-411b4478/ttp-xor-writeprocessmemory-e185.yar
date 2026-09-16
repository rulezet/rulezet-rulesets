rule TTP_XOR_WriteProcessMemory_e185 {
  strings:
    $key_e185 = { b6 f7 [2] 84 d5 [2] 82 e0 [2] ac e0 [2] 93 fc }

  condition:
    any of them
}