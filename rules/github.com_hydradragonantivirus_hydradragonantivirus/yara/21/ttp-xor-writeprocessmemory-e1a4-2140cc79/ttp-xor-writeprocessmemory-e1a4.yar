rule TTP_XOR_WriteProcessMemory_e1a4 {
  strings:
    $key_e1a4 = { b6 d6 [2] 84 f4 [2] 82 c1 [2] ac c1 [2] 93 dd }

  condition:
    any of them
}