rule TTP_XOR_WriteProcessMemory_e496 {
  strings:
    $key_e496 = { b3 e4 [2] 81 c6 [2] 87 f3 [2] a9 f3 [2] 96 ef }

  condition:
    any of them
}