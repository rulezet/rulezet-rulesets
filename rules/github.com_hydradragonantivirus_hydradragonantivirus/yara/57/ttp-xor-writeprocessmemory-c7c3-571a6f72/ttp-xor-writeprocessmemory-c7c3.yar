rule TTP_XOR_WriteProcessMemory_c7c3 {
  strings:
    $key_c7c3 = { 90 b1 [2] a2 93 [2] a4 a6 [2] 8a a6 [2] b5 ba }

  condition:
    any of them
}