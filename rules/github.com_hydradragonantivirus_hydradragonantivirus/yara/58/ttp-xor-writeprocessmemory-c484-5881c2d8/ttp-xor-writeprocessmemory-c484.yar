rule TTP_XOR_WriteProcessMemory_c484 {
  strings:
    $key_c484 = { 93 f6 [2] a1 d4 [2] a7 e1 [2] 89 e1 [2] b6 fd }

  condition:
    any of them
}