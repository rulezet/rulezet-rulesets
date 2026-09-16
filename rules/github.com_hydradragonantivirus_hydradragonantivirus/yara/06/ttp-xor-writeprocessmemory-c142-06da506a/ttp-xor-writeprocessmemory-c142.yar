rule TTP_XOR_WriteProcessMemory_c142 {
  strings:
    $key_c142 = { 96 30 [2] a4 12 [2] a2 27 [2] 8c 27 [2] b3 3b }

  condition:
    any of them
}