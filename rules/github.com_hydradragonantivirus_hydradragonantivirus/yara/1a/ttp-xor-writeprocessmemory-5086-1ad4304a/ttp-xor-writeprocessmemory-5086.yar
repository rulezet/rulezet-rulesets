rule TTP_XOR_WriteProcessMemory_5086 {
  strings:
    $key_5086 = { 07 f4 [2] 35 d6 [2] 33 e3 [2] 1d e3 [2] 22 ff }

  condition:
    any of them
}