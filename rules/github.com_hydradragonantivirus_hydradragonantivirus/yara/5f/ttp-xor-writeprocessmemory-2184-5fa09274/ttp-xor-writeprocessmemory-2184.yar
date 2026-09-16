rule TTP_XOR_WriteProcessMemory_2184 {
  strings:
    $key_2184 = { 76 f6 [2] 44 d4 [2] 42 e1 [2] 6c e1 [2] 53 fd }

  condition:
    any of them
}