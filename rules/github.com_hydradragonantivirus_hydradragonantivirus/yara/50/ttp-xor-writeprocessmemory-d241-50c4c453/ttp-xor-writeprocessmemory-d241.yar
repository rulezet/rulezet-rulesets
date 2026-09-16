rule TTP_XOR_WriteProcessMemory_d241 {
  strings:
    $key_d241 = { 85 33 [2] b7 11 [2] b1 24 [2] 9f 24 [2] a0 38 }

  condition:
    any of them
}