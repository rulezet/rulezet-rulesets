rule TTP_XOR_WriteProcessMemory_c7f6 {
  strings:
    $key_c7f6 = { 90 84 [2] a2 a6 [2] a4 93 [2] 8a 93 [2] b5 8f }

  condition:
    any of them
}