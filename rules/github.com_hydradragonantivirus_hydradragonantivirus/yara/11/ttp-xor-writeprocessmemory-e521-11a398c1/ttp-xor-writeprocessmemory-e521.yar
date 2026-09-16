rule TTP_XOR_WriteProcessMemory_e521 {
  strings:
    $key_e521 = { b2 53 [2] 80 71 [2] 86 44 [2] a8 44 [2] 97 58 }

  condition:
    any of them
}