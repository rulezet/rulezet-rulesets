rule TTP_XOR_WriteProcessMemory_e5e1 {
  strings:
    $key_e5e1 = { b2 93 [2] 80 b1 [2] 86 84 [2] a8 84 [2] 97 98 }

  condition:
    any of them
}