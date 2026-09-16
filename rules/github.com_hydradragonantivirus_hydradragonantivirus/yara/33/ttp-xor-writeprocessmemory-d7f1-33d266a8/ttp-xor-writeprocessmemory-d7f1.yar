rule TTP_XOR_WriteProcessMemory_d7f1 {
  strings:
    $key_d7f1 = { 80 83 [2] b2 a1 [2] b4 94 [2] 9a 94 [2] a5 88 }

  condition:
    any of them
}