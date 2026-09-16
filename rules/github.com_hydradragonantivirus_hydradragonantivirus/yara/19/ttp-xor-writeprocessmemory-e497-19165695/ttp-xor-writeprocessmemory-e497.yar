rule TTP_XOR_WriteProcessMemory_e497 {
  strings:
    $key_e497 = { b3 e5 [2] 81 c7 [2] 87 f2 [2] a9 f2 [2] 96 ee }

  condition:
    any of them
}