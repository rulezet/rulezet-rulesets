rule TTP_XOR_WriteProcessMemory_c416 {
  strings:
    $key_c416 = { 93 64 [2] a1 46 [2] a7 73 [2] 89 73 [2] b6 6f }

  condition:
    any of them
}