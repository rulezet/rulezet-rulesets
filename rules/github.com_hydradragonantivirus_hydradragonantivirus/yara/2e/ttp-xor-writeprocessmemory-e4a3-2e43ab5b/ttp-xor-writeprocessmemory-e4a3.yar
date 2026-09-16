rule TTP_XOR_WriteProcessMemory_e4a3 {
  strings:
    $key_e4a3 = { b3 d1 [2] 81 f3 [2] 87 c6 [2] a9 c6 [2] 96 da }

  condition:
    any of them
}