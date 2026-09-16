rule TTP_XOR_WriteProcessMemory_d6c1 {
  strings:
    $key_d6c1 = { 81 b3 [2] b3 91 [2] b5 a4 [2] 9b a4 [2] a4 b8 }

  condition:
    any of them
}