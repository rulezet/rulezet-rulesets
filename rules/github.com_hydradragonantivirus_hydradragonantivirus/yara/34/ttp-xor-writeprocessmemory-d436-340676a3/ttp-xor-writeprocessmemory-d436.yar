rule TTP_XOR_WriteProcessMemory_d436 {
  strings:
    $key_d436 = { 83 44 [2] b1 66 [2] b7 53 [2] 99 53 [2] a6 4f }

  condition:
    any of them
}