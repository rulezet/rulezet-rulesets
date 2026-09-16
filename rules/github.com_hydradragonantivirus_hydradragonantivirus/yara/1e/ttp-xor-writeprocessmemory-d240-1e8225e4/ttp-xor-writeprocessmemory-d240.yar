rule TTP_XOR_WriteProcessMemory_d240 {
  strings:
    $key_d240 = { 85 32 [2] b7 10 [2] b1 25 [2] 9f 25 [2] a0 39 }

  condition:
    any of them
}