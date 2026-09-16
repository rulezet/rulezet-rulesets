rule TTP_XOR_WriteProcessMemory_e542 {
  strings:
    $key_e542 = { b2 30 [2] 80 12 [2] 86 27 [2] a8 27 [2] 97 3b }

  condition:
    any of them
}