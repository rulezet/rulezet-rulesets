rule TTP_XOR_WriteProcessMemory_c561 {
  strings:
    $key_c561 = { 92 13 [2] a0 31 [2] a6 04 [2] 88 04 [2] b7 18 }

  condition:
    any of them
}