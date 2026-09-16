rule TTP_XOR_WriteProcessMemory_e572 {
  strings:
    $key_e572 = { b2 00 [2] 80 22 [2] 86 17 [2] a8 17 [2] 97 0b }

  condition:
    any of them
}