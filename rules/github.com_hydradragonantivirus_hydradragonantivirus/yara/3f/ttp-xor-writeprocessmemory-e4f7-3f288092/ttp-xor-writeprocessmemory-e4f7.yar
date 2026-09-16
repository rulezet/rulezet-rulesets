rule TTP_XOR_WriteProcessMemory_e4f7 {
  strings:
    $key_e4f7 = { b3 85 [2] 81 a7 [2] 87 92 [2] a9 92 [2] 96 8e }

  condition:
    any of them
}