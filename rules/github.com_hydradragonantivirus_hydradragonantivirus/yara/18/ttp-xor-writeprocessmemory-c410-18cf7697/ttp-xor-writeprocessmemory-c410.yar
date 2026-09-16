rule TTP_XOR_WriteProcessMemory_c410 {
  strings:
    $key_c410 = { 93 62 [2] a1 40 [2] a7 75 [2] 89 75 [2] b6 69 }

  condition:
    any of them
}