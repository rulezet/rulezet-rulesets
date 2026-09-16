rule TTP_XOR_WriteProcessMemory_c4c3 {
  strings:
    $key_c4c3 = { 93 b1 [2] a1 93 [2] a7 a6 [2] 89 a6 [2] b6 ba }

  condition:
    any of them
}