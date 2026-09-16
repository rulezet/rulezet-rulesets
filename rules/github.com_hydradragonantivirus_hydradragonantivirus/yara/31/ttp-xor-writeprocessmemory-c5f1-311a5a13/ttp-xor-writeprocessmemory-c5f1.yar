rule TTP_XOR_WriteProcessMemory_c5f1 {
  strings:
    $key_c5f1 = { 92 83 [2] a0 a1 [2] a6 94 [2] 88 94 [2] b7 88 }

  condition:
    any of them
}