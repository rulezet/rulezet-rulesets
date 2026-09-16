rule TTP_XOR_WriteProcessMemory_e551 {
  strings:
    $key_e551 = { b2 23 [2] 80 01 [2] 86 34 [2] a8 34 [2] 97 28 }

  condition:
    any of them
}