rule TTP_XOR_WriteProcessMemory_1084 {
  strings:
    $key_1084 = { 47 f6 [2] 75 d4 [2] 73 e1 [2] 5d e1 [2] 62 fd }

  condition:
    any of them
}