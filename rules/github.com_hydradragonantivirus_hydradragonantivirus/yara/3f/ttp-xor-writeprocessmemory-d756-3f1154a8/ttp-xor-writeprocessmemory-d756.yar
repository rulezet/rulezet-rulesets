rule TTP_XOR_WriteProcessMemory_d756 {
  strings:
    $key_d756 = { 80 24 [2] b2 06 [2] b4 33 [2] 9a 33 [2] a5 2f }

  condition:
    any of them
}