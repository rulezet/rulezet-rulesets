rule TTP_XOR_WriteProcessMemory_d600 {
  strings:
    $key_d600 = { 81 72 [2] b3 50 [2] b5 65 [2] 9b 65 [2] a4 79 }

  condition:
    any of them
}