rule TTP_XOR_WriteProcessMemory_1086 {
  strings:
    $key_1086 = { 47 f4 [2] 75 d6 [2] 73 e3 [2] 5d e3 [2] 62 ff }

  condition:
    any of them
}