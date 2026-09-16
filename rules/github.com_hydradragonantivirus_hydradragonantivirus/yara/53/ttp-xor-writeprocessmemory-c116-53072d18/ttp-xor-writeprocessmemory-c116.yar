rule TTP_XOR_WriteProcessMemory_c116 {
  strings:
    $key_c116 = { 96 64 [2] a4 46 [2] a2 73 [2] 8c 73 [2] b3 6f }

  condition:
    any of them
}