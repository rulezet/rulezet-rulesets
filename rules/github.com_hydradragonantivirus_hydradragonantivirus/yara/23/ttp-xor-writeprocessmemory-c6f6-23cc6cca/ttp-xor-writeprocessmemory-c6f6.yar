rule TTP_XOR_WriteProcessMemory_c6f6 {
  strings:
    $key_c6f6 = { 91 84 [2] a3 a6 [2] a5 93 [2] 8b 93 [2] b4 8f }

  condition:
    any of them
}