rule TTP_XOR_WriteProcessMemory_e1c7 {
  strings:
    $key_e1c7 = { b6 b5 [2] 84 97 [2] 82 a2 [2] ac a2 [2] 93 be }

  condition:
    any of them
}