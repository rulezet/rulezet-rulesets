rule TTP_XOR_WriteProcessMemory_d279 {
  strings:
    $key_d279 = { 85 0b [2] b7 29 [2] b1 1c [2] 9f 1c [2] a0 00 }

  condition:
    any of them
}