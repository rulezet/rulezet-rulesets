rule TTP_XOR_WriteProcessMemory_c732 {
  strings:
    $key_c732 = { 90 40 [2] a2 62 [2] a4 57 [2] 8a 57 [2] b5 4b }

  condition:
    any of them
}