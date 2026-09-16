rule TTP_XOR_WriteProcessMemory_d640 {
  strings:
    $key_d640 = { 81 32 [2] b3 10 [2] b5 25 [2] 9b 25 [2] a4 39 }

  condition:
    any of them
}