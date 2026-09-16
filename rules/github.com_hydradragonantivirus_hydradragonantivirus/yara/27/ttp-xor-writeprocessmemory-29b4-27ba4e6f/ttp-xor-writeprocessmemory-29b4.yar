rule TTP_XOR_WriteProcessMemory_29b4 {
  strings:
    $key_29b4 = { 7e c6 [2] 4c e4 [2] 4a d1 [2] 64 d1 [2] 5b cd }

  condition:
    any of them
}