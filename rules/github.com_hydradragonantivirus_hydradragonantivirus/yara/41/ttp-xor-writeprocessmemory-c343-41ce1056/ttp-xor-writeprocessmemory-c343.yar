rule TTP_XOR_WriteProcessMemory_c343 {
  strings:
    $key_c343 = { 94 31 [2] a6 13 [2] a0 26 [2] 8e 26 [2] b1 3a }

  condition:
    any of them
}