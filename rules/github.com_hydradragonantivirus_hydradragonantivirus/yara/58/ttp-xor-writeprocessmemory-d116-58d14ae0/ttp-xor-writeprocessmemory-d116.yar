rule TTP_XOR_WriteProcessMemory_d116 {
  strings:
    $key_d116 = { 86 64 [2] b4 46 [2] b2 73 [2] 9c 73 [2] a3 6f }

  condition:
    any of them
}