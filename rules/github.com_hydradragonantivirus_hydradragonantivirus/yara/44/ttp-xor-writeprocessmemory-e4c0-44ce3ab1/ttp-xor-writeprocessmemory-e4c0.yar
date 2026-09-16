rule TTP_XOR_WriteProcessMemory_e4c0 {
  strings:
    $key_e4c0 = { b3 b2 [2] 81 90 [2] 87 a5 [2] a9 a5 [2] 96 b9 }

  condition:
    any of them
}