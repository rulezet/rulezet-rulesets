rule TTP_XOR_WriteProcessMemory_c1f7 {
  strings:
    $key_c1f7 = { 96 85 [2] a4 a7 [2] a2 92 [2] 8c 92 [2] b3 8e }

  condition:
    any of them
}