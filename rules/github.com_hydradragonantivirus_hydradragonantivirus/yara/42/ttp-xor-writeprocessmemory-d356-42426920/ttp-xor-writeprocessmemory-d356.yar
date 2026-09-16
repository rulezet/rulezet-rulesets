rule TTP_XOR_WriteProcessMemory_d356 {
  strings:
    $key_d356 = { 84 24 [2] b6 06 [2] b0 33 [2] 9e 33 [2] a1 2f }

  condition:
    any of them
}