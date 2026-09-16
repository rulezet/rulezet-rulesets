rule TTP_XOR_WriteProcessMemory_d6c3 {
  strings:
    $key_d6c3 = { 81 b1 [2] b3 93 [2] b5 a6 [2] 9b a6 [2] a4 ba }

  condition:
    any of them
}