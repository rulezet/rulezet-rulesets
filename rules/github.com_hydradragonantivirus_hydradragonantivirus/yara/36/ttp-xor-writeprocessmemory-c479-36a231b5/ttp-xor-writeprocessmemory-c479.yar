rule TTP_XOR_WriteProcessMemory_c479 {
  strings:
    $key_c479 = { 93 0b [2] a1 29 [2] a7 1c [2] 89 1c [2] b6 00 }

  condition:
    any of them
}