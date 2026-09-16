rule TTP_XOR_WriteProcessMemory_c7f1 {
  strings:
    $key_c7f1 = { 90 83 [2] a2 a1 [2] a4 94 [2] 8a 94 [2] b5 88 }

  condition:
    any of them
}