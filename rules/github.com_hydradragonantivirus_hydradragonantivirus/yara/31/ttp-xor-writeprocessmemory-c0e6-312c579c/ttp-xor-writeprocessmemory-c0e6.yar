rule TTP_XOR_WriteProcessMemory_c0e6 {
  strings:
    $key_c0e6 = { 97 94 [2] a5 b6 [2] a3 83 [2] 8d 83 [2] b2 9f }

  condition:
    any of them
}