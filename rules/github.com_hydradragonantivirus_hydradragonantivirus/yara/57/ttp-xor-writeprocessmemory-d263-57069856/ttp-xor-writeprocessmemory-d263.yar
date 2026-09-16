rule TTP_XOR_WriteProcessMemory_d263 {
  strings:
    $key_d263 = { 85 11 [2] b7 33 [2] b1 06 [2] 9f 06 [2] a0 1a }

  condition:
    any of them
}