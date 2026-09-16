rule TTP_XOR_WriteProcessMemory_c146 {
  strings:
    $key_c146 = { 96 34 [2] a4 16 [2] a2 23 [2] 8c 23 [2] b3 3f }

  condition:
    any of them
}