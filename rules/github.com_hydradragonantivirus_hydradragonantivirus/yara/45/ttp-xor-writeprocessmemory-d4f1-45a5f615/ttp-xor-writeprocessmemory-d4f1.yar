rule TTP_XOR_WriteProcessMemory_d4f1 {
  strings:
    $key_d4f1 = { 83 83 [2] b1 a1 [2] b7 94 [2] 99 94 [2] a6 88 }

  condition:
    any of them
}