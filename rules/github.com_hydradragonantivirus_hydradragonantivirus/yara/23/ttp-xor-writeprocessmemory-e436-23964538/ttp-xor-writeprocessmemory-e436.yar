rule TTP_XOR_WriteProcessMemory_e436 {
  strings:
    $key_e436 = { b3 44 [2] 81 66 [2] 87 53 [2] a9 53 [2] 96 4f }

  condition:
    any of them
}