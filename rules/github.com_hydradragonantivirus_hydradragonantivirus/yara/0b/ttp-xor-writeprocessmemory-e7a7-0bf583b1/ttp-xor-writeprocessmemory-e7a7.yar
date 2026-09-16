rule TTP_XOR_WriteProcessMemory_e7a7 {
  strings:
    $key_e7a7 = { b0 d5 [2] 82 f7 [2] 84 c2 [2] aa c2 [2] 95 de }

  condition:
    any of them
}