rule TTP_XOR_WriteProcessMemory_c4f2 {
  strings:
    $key_c4f2 = { 93 80 [2] a1 a2 [2] a7 97 [2] 89 97 [2] b6 8b }

  condition:
    any of them
}