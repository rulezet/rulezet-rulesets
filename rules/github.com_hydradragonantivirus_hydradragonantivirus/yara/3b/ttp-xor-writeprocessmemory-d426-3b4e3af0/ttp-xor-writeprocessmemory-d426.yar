rule TTP_XOR_WriteProcessMemory_d426 {
  strings:
    $key_d426 = { 83 54 [2] b1 76 [2] b7 43 [2] 99 43 [2] a6 5f }

  condition:
    any of them
}