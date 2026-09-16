rule TTP_XOR_WriteProcessMemory_d6a3 {
  strings:
    $key_d6a3 = { 81 d1 [2] b3 f3 [2] b5 c6 [2] 9b c6 [2] a4 da }

  condition:
    any of them
}