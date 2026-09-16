rule TTP_XOR_WriteProcessMemory_e125 {
  strings:
    $key_e125 = { b6 57 [2] 84 75 [2] 82 40 [2] ac 40 [2] 93 5c }

  condition:
    any of them
}