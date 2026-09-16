rule TTP_XOR_WriteProcessMemory_c568 {
  strings:
    $key_c568 = { 92 1a [2] a0 38 [2] a6 0d [2] 88 0d [2] b7 11 }

  condition:
    any of them
}