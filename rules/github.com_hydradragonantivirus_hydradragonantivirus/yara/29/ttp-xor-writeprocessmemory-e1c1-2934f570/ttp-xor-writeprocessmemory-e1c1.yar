rule TTP_XOR_WriteProcessMemory_e1c1 {
  strings:
    $key_e1c1 = { b6 b3 [2] 84 91 [2] 82 a4 [2] ac a4 [2] 93 b8 }

  condition:
    any of them
}