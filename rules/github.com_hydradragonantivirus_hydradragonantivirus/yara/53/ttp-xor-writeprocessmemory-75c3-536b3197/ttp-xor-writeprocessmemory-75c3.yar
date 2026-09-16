rule TTP_XOR_WriteProcessMemory_75c3 {
  strings:
    $key_75c3 = { 22 b1 [2] 10 93 [2] 16 a6 [2] 38 a6 [2] 07 ba }

  condition:
    any of them
}