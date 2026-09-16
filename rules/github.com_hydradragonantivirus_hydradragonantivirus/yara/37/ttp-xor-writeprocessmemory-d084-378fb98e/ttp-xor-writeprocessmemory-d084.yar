rule TTP_XOR_WriteProcessMemory_d084 {
  strings:
    $key_d084 = { 87 f6 [2] b5 d4 [2] b3 e1 [2] 9d e1 [2] a2 fd }

  condition:
    any of them
}