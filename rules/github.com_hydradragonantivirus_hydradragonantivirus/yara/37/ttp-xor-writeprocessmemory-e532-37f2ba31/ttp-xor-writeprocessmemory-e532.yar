rule TTP_XOR_WriteProcessMemory_e532 {
  strings:
    $key_e532 = { b2 40 [2] 80 62 [2] 86 57 [2] a8 57 [2] 97 4b }

  condition:
    any of them
}