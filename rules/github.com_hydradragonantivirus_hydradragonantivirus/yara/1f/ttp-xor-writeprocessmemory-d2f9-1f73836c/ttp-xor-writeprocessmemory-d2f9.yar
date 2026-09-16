rule TTP_XOR_WriteProcessMemory_d2f9 {
  strings:
    $key_d2f9 = { 85 8b [2] b7 a9 [2] b1 9c [2] 9f 9c [2] a0 80 }

  condition:
    any of them
}