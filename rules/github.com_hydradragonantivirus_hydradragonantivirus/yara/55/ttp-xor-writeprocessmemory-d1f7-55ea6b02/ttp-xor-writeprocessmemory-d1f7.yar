rule TTP_XOR_WriteProcessMemory_d1f7 {
  strings:
    $key_d1f7 = { 86 85 [2] b4 a7 [2] b2 92 [2] 9c 92 [2] a3 8e }

  condition:
    any of them
}