rule TTP_XOR_WriteProcessMemory_c6e6 {
  strings:
    $key_c6e6 = { 91 94 [2] a3 b6 [2] a5 83 [2] 8b 83 [2] b4 9f }

  condition:
    any of them
}