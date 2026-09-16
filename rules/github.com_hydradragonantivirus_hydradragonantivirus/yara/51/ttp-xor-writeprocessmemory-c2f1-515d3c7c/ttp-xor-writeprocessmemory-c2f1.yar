rule TTP_XOR_WriteProcessMemory_c2f1 {
  strings:
    $key_c2f1 = { 95 83 [2] a7 a1 [2] a1 94 [2] 8f 94 [2] b0 88 }

  condition:
    any of them
}