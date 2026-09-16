rule TTP_XOR_WriteProcessMemory_c0e1 {
  strings:
    $key_c0e1 = { 97 93 [2] a5 b1 [2] a3 84 [2] 8d 84 [2] b2 98 }

  condition:
    any of them
}