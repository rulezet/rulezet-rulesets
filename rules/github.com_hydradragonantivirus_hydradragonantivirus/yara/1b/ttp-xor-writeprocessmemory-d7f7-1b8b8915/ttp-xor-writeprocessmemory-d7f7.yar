rule TTP_XOR_WriteProcessMemory_d7f7 {
  strings:
    $key_d7f7 = { 80 85 [2] b2 a7 [2] b4 92 [2] 9a 92 [2] a5 8e }

  condition:
    any of them
}