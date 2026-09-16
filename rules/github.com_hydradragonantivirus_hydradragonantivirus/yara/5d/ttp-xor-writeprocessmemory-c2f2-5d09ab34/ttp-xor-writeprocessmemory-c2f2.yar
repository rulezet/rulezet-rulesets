rule TTP_XOR_WriteProcessMemory_c2f2 {
  strings:
    $key_c2f2 = { 95 80 [2] a7 a2 [2] a1 97 [2] 8f 97 [2] b0 8b }

  condition:
    any of them
}