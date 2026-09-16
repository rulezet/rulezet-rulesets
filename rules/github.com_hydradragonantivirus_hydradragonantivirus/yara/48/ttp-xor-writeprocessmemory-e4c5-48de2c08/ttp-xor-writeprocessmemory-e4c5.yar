rule TTP_XOR_WriteProcessMemory_e4c5 {
  strings:
    $key_e4c5 = { b3 b7 [2] 81 95 [2] 87 a0 [2] a9 a0 [2] 96 bc }

  condition:
    any of them
}