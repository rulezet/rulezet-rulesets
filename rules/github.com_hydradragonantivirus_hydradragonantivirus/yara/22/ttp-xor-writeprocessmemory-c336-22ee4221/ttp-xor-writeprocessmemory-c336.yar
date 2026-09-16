rule TTP_XOR_WriteProcessMemory_c336 {
  strings:
    $key_c336 = { 94 44 [2] a6 66 [2] a0 53 [2] 8e 53 [2] b1 4f }

  condition:
    any of them
}