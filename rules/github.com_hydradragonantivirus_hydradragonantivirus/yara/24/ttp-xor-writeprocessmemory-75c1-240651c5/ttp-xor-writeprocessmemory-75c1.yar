rule TTP_XOR_WriteProcessMemory_75c1 {
  strings:
    $key_75c1 = { 22 b3 [2] 10 91 [2] 16 a4 [2] 38 a4 [2] 07 b8 }

  condition:
    any of them
}