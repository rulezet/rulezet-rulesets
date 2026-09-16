rule TTP_XOR_WriteProcessMemory_c100 {
  strings:
    $key_c100 = { 96 72 [2] a4 50 [2] a2 65 [2] 8c 65 [2] b3 79 }

  condition:
    any of them
}