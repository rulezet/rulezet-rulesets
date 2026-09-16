rule TTP_XOR_WriteProcessMemory_e4a4 {
  strings:
    $key_e4a4 = { b3 d6 [2] 81 f4 [2] 87 c1 [2] a9 c1 [2] 96 dd }

  condition:
    any of them
}