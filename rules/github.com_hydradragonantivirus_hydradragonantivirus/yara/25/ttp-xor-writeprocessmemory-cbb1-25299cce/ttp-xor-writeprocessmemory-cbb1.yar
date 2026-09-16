rule TTP_XOR_WriteProcessMemory_cbb1 {
  strings:
    $key_cbb1 = { 9c c3 [2] ae e1 [2] a8 d4 [2] 86 d4 [2] b9 c8 }

  condition:
    any of them
}