rule TTP_XOR_WriteProcessMemory_d270 {
  strings:
    $key_d270 = { 85 02 [2] b7 20 [2] b1 15 [2] 9f 15 [2] a0 09 }

  condition:
    any of them
}