rule TTP_XOR_WriteProcessMemory_c560 {
  strings:
    $key_c560 = { 92 12 [2] a0 30 [2] a6 05 [2] 88 05 [2] b7 19 }

  condition:
    any of them
}