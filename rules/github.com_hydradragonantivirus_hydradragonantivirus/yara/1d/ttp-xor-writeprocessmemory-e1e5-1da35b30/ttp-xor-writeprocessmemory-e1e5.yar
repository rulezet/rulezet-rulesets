rule TTP_XOR_WriteProcessMemory_e1e5 {
  strings:
    $key_e1e5 = { b6 97 [2] 84 b5 [2] 82 80 [2] ac 80 [2] 93 9c }

  condition:
    any of them
}