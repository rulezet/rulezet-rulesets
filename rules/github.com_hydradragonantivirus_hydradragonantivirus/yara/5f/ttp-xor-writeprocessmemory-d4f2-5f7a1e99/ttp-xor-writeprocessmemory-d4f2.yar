rule TTP_XOR_WriteProcessMemory_d4f2 {
  strings:
    $key_d4f2 = { 83 80 [2] b1 a2 [2] b7 97 [2] 99 97 [2] a6 8b }

  condition:
    any of them
}