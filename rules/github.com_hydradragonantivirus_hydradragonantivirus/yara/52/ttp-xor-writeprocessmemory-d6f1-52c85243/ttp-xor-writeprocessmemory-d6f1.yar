rule TTP_XOR_WriteProcessMemory_d6f1 {
  strings:
    $key_d6f1 = { 81 83 [2] b3 a1 [2] b5 94 [2] 9b 94 [2] a4 88 }

  condition:
    any of them
}