rule TTP_XOR_WriteProcessMemory_d1f1 {
  strings:
    $key_d1f1 = { 86 83 [2] b4 a1 [2] b2 94 [2] 9c 94 [2] a3 88 }

  condition:
    any of them
}