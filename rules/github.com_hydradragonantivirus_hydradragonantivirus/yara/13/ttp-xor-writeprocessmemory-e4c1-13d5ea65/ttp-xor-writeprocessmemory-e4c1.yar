rule TTP_XOR_WriteProcessMemory_e4c1 {
  strings:
    $key_e4c1 = { b3 b3 [2] 81 91 [2] 87 a4 [2] a9 a4 [2] 96 b8 }

  condition:
    any of them
}