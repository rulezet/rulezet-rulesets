rule TTP_XOR_WriteProcessMemory_d141 {
  strings:
    $key_d141 = { 86 33 [2] b4 11 [2] b2 24 [2] 9c 24 [2] a3 38 }

  condition:
    any of them
}