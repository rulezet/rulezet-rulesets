rule TTP_XOR_WriteProcessMemory_c4f1 {
  strings:
    $key_c4f1 = { 93 83 [2] a1 a1 [2] a7 94 [2] 89 94 [2] b6 88 }

  condition:
    any of them
}