rule TTP_XOR_WriteProcessMemory_e5d1 {
  strings:
    $key_e5d1 = { b2 a3 [2] 80 81 [2] 86 b4 [2] a8 b4 [2] 97 a8 }

  condition:
    any of them
}