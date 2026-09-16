rule TTP_XOR_WriteProcessMemory_c700 {
  strings:
    $key_c700 = { 90 72 [2] a2 50 [2] a4 65 [2] 8a 65 [2] b5 79 }

  condition:
    any of them
}