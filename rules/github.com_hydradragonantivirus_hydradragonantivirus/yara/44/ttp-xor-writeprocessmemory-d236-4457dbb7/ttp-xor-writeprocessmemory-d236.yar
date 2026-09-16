rule TTP_XOR_WriteProcessMemory_d236 {
  strings:
    $key_d236 = { 85 44 [2] b7 66 [2] b1 53 [2] 9f 53 [2] a0 4f }

  condition:
    any of them
}