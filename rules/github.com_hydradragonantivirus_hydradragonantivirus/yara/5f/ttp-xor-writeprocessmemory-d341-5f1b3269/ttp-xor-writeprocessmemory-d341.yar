rule TTP_XOR_WriteProcessMemory_d341 {
  strings:
    $key_d341 = { 84 33 [2] b6 11 [2] b0 24 [2] 9e 24 [2] a1 38 }

  condition:
    any of them
}