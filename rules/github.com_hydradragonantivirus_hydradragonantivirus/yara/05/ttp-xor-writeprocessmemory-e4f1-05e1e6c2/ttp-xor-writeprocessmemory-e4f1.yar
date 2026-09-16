rule TTP_XOR_WriteProcessMemory_e4f1 {
  strings:
    $key_e4f1 = { b3 83 [2] 81 a1 [2] 87 94 [2] a9 94 [2] 96 88 }

  condition:
    any of them
}