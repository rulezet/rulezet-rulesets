rule TTP_XOR_WriteProcessMemory_d245 {
  strings:
    $key_d245 = { 85 37 [2] b7 15 [2] b1 20 [2] 9f 20 [2] a0 3c }

  condition:
    any of them
}