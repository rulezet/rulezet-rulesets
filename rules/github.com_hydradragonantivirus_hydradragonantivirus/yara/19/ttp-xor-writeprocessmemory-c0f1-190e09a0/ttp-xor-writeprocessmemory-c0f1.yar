rule TTP_XOR_WriteProcessMemory_c0f1 {
  strings:
    $key_c0f1 = { 97 83 [2] a5 a1 [2] a3 94 [2] 8d 94 [2] b2 88 }

  condition:
    any of them
}