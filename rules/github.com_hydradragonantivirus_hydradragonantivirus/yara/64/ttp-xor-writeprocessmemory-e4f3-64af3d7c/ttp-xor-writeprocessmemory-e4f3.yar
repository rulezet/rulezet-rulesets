rule TTP_XOR_WriteProcessMemory_e4f3 {
  strings:
    $key_e4f3 = { b3 81 [2] 81 a3 [2] 87 96 [2] a9 96 [2] 96 8a }

  condition:
    any of them
}