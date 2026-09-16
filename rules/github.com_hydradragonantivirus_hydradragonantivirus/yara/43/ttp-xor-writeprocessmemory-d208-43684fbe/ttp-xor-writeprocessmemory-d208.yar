rule TTP_XOR_WriteProcessMemory_d208 {
  strings:
    $key_d208 = { 85 7a [2] b7 58 [2] b1 6d [2] 9f 6d [2] a0 71 }

  condition:
    any of them
}