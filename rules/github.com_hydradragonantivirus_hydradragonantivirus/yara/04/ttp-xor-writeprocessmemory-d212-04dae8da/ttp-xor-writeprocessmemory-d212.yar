rule TTP_XOR_WriteProcessMemory_d212 {
  strings:
    $key_d212 = { 85 60 [2] b7 42 [2] b1 77 [2] 9f 77 [2] a0 6b }

  condition:
    any of them
}