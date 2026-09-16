rule TTP_XOR_WriteProcessMemory_c571 {
  strings:
    $key_c571 = { 92 03 [2] a0 21 [2] a6 14 [2] 88 14 [2] b7 08 }

  condition:
    any of them
}