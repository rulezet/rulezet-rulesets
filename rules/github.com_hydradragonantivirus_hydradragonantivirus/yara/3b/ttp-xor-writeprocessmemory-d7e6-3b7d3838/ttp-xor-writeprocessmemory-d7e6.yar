rule TTP_XOR_WriteProcessMemory_d7e6 {
  strings:
    $key_d7e6 = { 80 94 [2] b2 b6 [2] b4 83 [2] 9a 83 [2] a5 9f }

  condition:
    any of them
}