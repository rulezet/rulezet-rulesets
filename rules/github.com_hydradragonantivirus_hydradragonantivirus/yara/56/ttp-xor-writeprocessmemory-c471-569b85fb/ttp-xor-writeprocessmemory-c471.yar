rule TTP_XOR_WriteProcessMemory_c471 {
  strings:
    $key_c471 = { 93 03 [2] a1 21 [2] a7 14 [2] 89 14 [2] b6 08 }

  condition:
    any of them
}