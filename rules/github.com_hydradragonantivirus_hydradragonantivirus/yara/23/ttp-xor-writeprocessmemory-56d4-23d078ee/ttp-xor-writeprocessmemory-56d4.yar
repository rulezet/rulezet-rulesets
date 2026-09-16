rule TTP_XOR_WriteProcessMemory_56d4 {
  strings:
    $key_56d4 = { 01 a6 [2] 33 84 [2] 35 b1 [2] 1b b1 [2] 24 ad }

  condition:
    any of them
}