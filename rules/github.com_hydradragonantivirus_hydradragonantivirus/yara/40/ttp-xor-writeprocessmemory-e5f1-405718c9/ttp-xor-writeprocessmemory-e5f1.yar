rule TTP_XOR_WriteProcessMemory_e5f1 {
  strings:
    $key_e5f1 = { b2 83 [2] 80 a1 [2] 86 94 [2] a8 94 [2] 97 88 }

  condition:
    any of them
}